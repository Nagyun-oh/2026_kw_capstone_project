package com.example.security_log_system.recovery;

import com.example.security_log_system.config.KafkaConsumerConfig;
import com.example.security_log_system.config.KafkaProducerConfig;
import com.example.security_log_system.config.PipelineKafkaErrorConfig;
import com.example.security_log_system.dto.AiRequestDto;
import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.kafka.AiRequestProducer;
import com.example.security_log_system.kafka.AiResultConsumer;
import com.example.security_log_system.repository.*;
import com.example.security_log_system.service.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.persistence.EntityManagerFactory;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.kafka.core.*;
import org.springframework.kafka.listener.*;
import org.springframework.kafka.test.EmbeddedKafkaKraftBroker;
import org.springframework.kafka.test.utils.ContainerTestUtils;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.orm.jpa.*;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.io.File;
import java.net.ServerSocket;
import java.net.URLClassLoader;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

/** 기존 DB·브로커 대신 전용 MySQL 스키마와 embedded Kafka에서만 실행한다. */
@SpringJUnitConfig(RecoveryVerificationTest.Config.class)
@EnabledIfEnvironmentVariable(named="DG_RECOVERY_DB_URL", matches="jdbc:mysql://127\\.0\\.0\\.1:3306/dg_recovery_[a-z0-9_]+\\?serverTimezone=Asia/Seoul")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class RecoveryVerificationTest {
    static final ObjectMapper JSON = new ObjectMapper();
    static EmbeddedKafkaKraftBroker broker;
    @Autowired LogService logs;
    @Autowired ThreatService threats;
    @Autowired AiRequestOutboxService outbox;
    @Autowired RequestAlertPublisher alerts;
    @Autowired SimpMessagingTemplate messaging;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactionManager;

    @Configuration
    @EnableTransactionManagement
    @EnableJpaRepositories(basePackageClasses=LogRepository.class)
    static class Config {
        @Bean DataSource dataSource() {
            String url=System.getenv("DG_RECOVERY_DB_URL");
            if(url==null || !url.matches("jdbc:mysql://127\\.0\\.0\\.1:3306/dg_recovery_[a-z0-9_]+\\?serverTimezone=Asia/Seoul"))
                throw new IllegalStateException("Isolated recovery database required");
            return new DriverManagerDataSource(url, System.getenv("DG_RECOVERY_DB_USER"), System.getenv("DG_RECOVERY_DB_PASSWORD"));
        }
        @Bean LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource ds) {
            var f=new LocalContainerEntityManagerFactoryBean(); f.setDataSource(ds);
            f.setPackagesToScan(LogEntry.class.getPackageName());
            f.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
            f.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto","validate","hibernate.show_sql","false",
                    "hibernate.physical_naming_strategy","org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy"));
            return f;
        }
        @Bean PlatformTransactionManager transactionManager(EntityManagerFactory f) { return new JpaTransactionManager(f); }
        @Bean JdbcTemplate jdbcTemplate(DataSource ds) { return new JdbcTemplate(ds); }
        @Bean ObjectMapper mapper() { return JSON; }
        @Bean MeterRegistry meterRegistry() { return new SimpleMeterRegistry(); }
        @Bean PipelineTrace trace(ObjectMapper m) { return new PipelineTrace(true,m); }
        @Bean AiRequestOutboxRepository outboxRepository(JdbcTemplate j) { return new AiRequestOutboxRepository(j); }
        // 이 검증은 발행기를 직접 호출하므로 커밋 후 깨우기는 동작하지 않는 대역을 쓴다.
        @Bean AiRequestOutboxService outboxService(AiRequestOutboxRepository r,ObjectMapper m) { return new AiRequestOutboxService(r,m,mock(AiRequestOutboxWakeup.class)); }
        @Bean RequestAlertRepository alertRepository(JdbcTemplate j) { return new RequestAlertRepository(j); }
        @Bean RequestAlertService alertService(RequestAlertRepository r) { return new RequestAlertService(r,mock(RequestAlertWakeup.class)); }
        @Bean RequestCorrelationService correlation(JdbcTemplate j,LogRepository l,WafDetectionRepository w) { return new RequestCorrelationService(j,l,w); }
        @Bean SimpMessagingTemplate messaging() { return mock(SimpMessagingTemplate.class); }
        @Bean RequestAlertPublisher alertPublisher(RequestAlertRepository r,SimpMessagingTemplate m,PipelineTrace p) { return new RequestAlertPublisher(r,m,p); }
        @Bean LogService logService(LogRepository r,AiRequestOutboxService o,RequestCorrelationService c,ObjectMapper m,PipelineTrace p) {
            return new LogService(r,mock(BlacklistService.class),o,c,m,p);
        }
        @Bean ThreatService threatService(LogRepository l,ThreatRepository t,MeterRegistry m,RequestCorrelationService c,RequestAlertService a,PipelineTrace p) {
            return new ThreatService(l,t,mock(AutoBlacklistPolicyService.class),mock(NotificationService.class),m,c,a,p);
        }
    }

    @BeforeAll static void startBroker() {
        broker=new EmbeddedKafkaKraftBroker(1,1,"ai-request-topic","ai-result-topic","ai-result-topic.DLT","log-topic","log-topic.DLT");
        broker.brokerProperties(Map.of("auto.create.topics.enable","false","num.network.threads","2","num.io.threads","2"));
        broker.afterPropertiesSet();
    }
    @AfterAll static void stopBroker() { if(broker!=null) broker.destroy(); }
    @BeforeEach void cleanOnlyIsolatedFixtures() {
        for(String table:List.of("ai_request_outbox","request_alerts","waf_detections","ip_blacklist","detected_threats","network_logs","request_correlations"))
            jdbc.update("DELETE FROM "+table);
        clearInvocations(messaging);
    }
    static String rid() { return UUID.randomUUID().toString().replace("-",""); }
    static String message(String id) throws Exception {
        return JSON.writeValueAsString(Map.of("request_id",id,"remote_addr","192.0.2.123","method","GET","path","/?recovery="+id,"status",200,"http_user_agent","DualGuard-Recovery-Test","request_body",""));
    }
    long fixture(String id) throws Exception { logs.processRawLog(message(id)); return jdbc.queryForObject("SELECT id FROM network_logs WHERE request_id=?",Long.class,id); }
    String state(long id) { return jdbc.queryForObject("SELECT state FROM ai_request_outbox WHERE log_id=?",String.class,id); }
    static void await(BooleanSupplier check,int seconds) throws Exception {
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds);
        while(System.nanoTime()<until) { if(check.getAsBoolean()) return; Thread.sleep(200); }
        assertThat(check.getAsBoolean()).as("bounded recovery condition").isTrue();
    }
    static void evidence(String name,Map<String,?> observations) throws Exception {
        Path out=Path.of(System.getenv("DG_RECOVERY_OUTPUT")).toAbsolutePath().normalize();
        Files.writeString(out.resolve("observations.jsonl"),JSON.writeValueAsString(Map.of("case",name,"at",java.time.Instant.now().toString(),"observations",observations))+"\n",StandardOpenOption.CREATE,StandardOpenOption.APPEND);
    }
    static DefaultKafkaProducerFactory<String,String> factory(String bootstrap) {
        KafkaProducerConfig c=new KafkaProducerConfig(); ReflectionTestUtils.setField(c,"bootstrapServers",bootstrap);
        return (DefaultKafkaProducerFactory<String,String>)c.producerFactory();
    }
    AiRequestOutboxPublisher publisher(KafkaTemplate<String,String> t) { return new AiRequestOutboxPublisher(outbox,new AiRequestProducer(t,new SimpleMeterRegistry())); }
    static KafkaConsumer<String,String> consumer() {
        return new KafkaConsumer<>(Map.of(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG,broker.getBrokersAsString(),ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG,false,ConsumerConfig.AUTO_OFFSET_RESET_CONFIG,"earliest"),new StringDeserializer(),new StringDeserializer());
    }
    static long requestCount(long id) throws Exception {
        try(var c=consumer()) {
            var tp=new TopicPartition("ai-request-topic",0); c.assign(List.of(tp)); c.seekToBeginning(List.of(tp));
            long end=c.endOffsets(List.of(tp)).get(tp), count=0, deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(c.position(tp)<end && System.nanoTime()<deadline)
                for(var r:c.poll(Duration.ofMillis(200))) if(r.offset()<end && Long.toString(id).equals(r.key())) count++;
            assertThat(c.position(tp)).isGreaterThanOrEqualTo(end); return count;
        }
    }

    @Test @Order(1) @DisplayName("실제 JPA 로그·JDBC outbox는 같은 트랜잭션에서 함께 롤백된다")
    void rollbackIsAtomic() throws Exception {
        String id=rid(), text=message(id); var tx=new TransactionTemplate(transactionManager);
        assertThatThrownBy(()->tx.execute(s->{ logs.processRawLog(text);
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ai_request_outbox",Integer.class)).isEqualTo(1);
            assertThat(outbox.claimNext()).isEmpty();
            throw new IllegalStateException("intentional isolated rollback");
        })).isInstanceOf(IllegalStateException.class).hasMessage("intentional isolated rollback");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM network_logs",Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ai_request_outbox",Integer.class)).isZero();
        evidence("atomic_rollback",Map.of("logs",0,"outbox",0,"uncommitted_claim_visible",false));
    }
    @Test @Order(2) @DisplayName("커밋 전에는 선점 불가하고 커밋 후 실제 Kafka 발행이 가능하다")
    void committedVisibility() throws Exception {
        long id=fixture(rid()); assertThat(state(id)).isEqualTo("PENDING");
        var pf=factory(broker.getBrokersAsString());
        try { assertThat(publisher(new KafkaTemplate<>(pf)).publishNext()).isTrue();
            assertThat(state(id)).isEqualTo("SENT"); assertThat(requestCount(id)).isEqualTo(1);
            evidence("committed_publish",Map.of("logId",id,"state","SENT","broker_records",1));
        } finally { pf.destroy(); }
    }
    @Test @Order(3) @DisplayName("실제 Kafka 접속 실패 후 작업 보존·백오프·접속 복구 후 재전송을 확인한다")
    void unreachableKafkaRecovers() throws Exception {
        long id=fixture(rid()); int port; try(var socket=new ServerSocket(0)){port=socket.getLocalPort();}
        var pf=factory("127.0.0.1:"+port); var p=publisher(new KafkaTemplate<>(pf));
        try { assertThat(p.publishNext()).isFalse(); assertThat(state(id)).isEqualTo("PENDING");
            assertThat(jdbc.queryForObject("SELECT attempts FROM ai_request_outbox WHERE log_id=?",Long.class,id)).isEqualTo(1L);
            assertThat(jdbc.queryForObject("SELECT published_at IS NULL FROM ai_request_outbox WHERE log_id=?",Boolean.class,id)).isTrue();
            pf.updateConfigs(Map.of(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,broker.getBrokersAsString())); pf.reset();
            long began=System.nanoTime();
            await(()->p.publishNext(),20);
            assertThat(state(id)).isEqualTo("SENT"); assertThat(requestCount(id)).isEqualTo(1);
            evidence("network_recovery",Map.of("logId",id,"failure_state","PENDING","final_state","SENT","attempts",2,"recovery_seconds",(System.nanoTime()-began)/1e9,"fault","isolated producer closed TCP port; real broker unchanged"));
        } finally { pf.destroy(); }
    }

    static int worker(String mode,String id,int timeout) throws Exception {
        LinkedHashSet<String> cp=new LinkedHashSet<>();
        for(ClassLoader l=RecoveryVerificationTest.class.getClassLoader();l!=null;l=l.getParent())
            if(l instanceof URLClassLoader u) for(var url:u.getURLs()) if(url.getProtocol().equals("file")) cp.add(Path.of(url.toURI()).toString());
        cp.addAll(Arrays.asList(System.getProperty("java.class.path").split(java.util.regex.Pattern.quote(File.pathSeparator))));
        Path out=Path.of(System.getenv("DG_RECOVERY_OUTPUT")); String tag=mode+"-"+id;
        Path args=out.resolve(tag+".args");
        String classpath=String.join(File.pathSeparator,cp).replace("\\","\\\\").replace("\"","\\\"");
        Files.writeString(args,"-Xmx384m\n-cp\n\""+classpath+"\"\n"+Worker.class.getName()+"\n"+mode+"\n"+id+"\n");
        var b=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java.exe").toString(),"@"+args.toAbsolutePath());
        b.environment().put("DG_RECOVERY_KAFKA",broker.getBrokersAsString());
        b.redirectErrorStream(true).redirectOutput(out.resolve(tag+".log").toFile());
        Process process=b.start();
        if(!process.waitFor(timeout,TimeUnit.SECONDS)){process.destroyForcibly();throw new IllegalStateException("Owned worker timeout");}
        return process.exitValue();
    }
    @Test @Order(4) @DisplayName("발행 전 JVM 강제 종료 후 새 JVM이 PENDING 작업을 전송한다")
    void pendingSurvivesProcessExit() throws Exception {
        String r=rid(); assertThat(worker("enqueue-halt",r,40)).isEqualTo(23);
        long id=jdbc.queryForObject("SELECT id FROM network_logs WHERE request_id=?",Long.class,r);
        assertThat(state(id)).isEqualTo("PENDING");
        assertThat(worker("publish",r,100)).isZero(); assertThat(state(id)).isEqualTo("SENT");
        assertThat(requestCount(id)).isEqualTo(1);
        evidence("pending_restart",Map.of("logId",id,"first_exit",23,"second_exit",0,"final_state","SENT","broker_records",1));
    }
    @Test @Order(5) @DisplayName("선점 직후 JVM 종료 시 실제 60초 리스 만료 후 새 JVM이 복구한다")
    void inflightLeaseSurvivesProcessExit() throws Exception {
        String r=rid(); long id=fixture(r); assertThat(worker("claim-halt",r,40)).isEqualTo(24);
        assertThat(state(id)).isEqualTo("IN_FLIGHT");
        String old=jdbc.queryForObject("SELECT lease_token FROM ai_request_outbox WHERE log_id=?",String.class,id);
        long began=System.nanoTime(); assertThat(worker("publish",r,110)).isZero();
        assertThat(state(id)).isEqualTo("SENT"); assertThat(requestCount(id)).isEqualTo(1);
        assertThatThrownBy(()->outbox.markSent(new AiRequestOutboxService.Job(id,"{}",old,1)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("ownership changed");
        evidence("lease_restart",Map.of("logId",id,"lease_seconds",60,"recovery_seconds",(System.nanoTime()-began)/1e9,"attempts",2,"stale_owner_rejected",true));
    }
    @Test @Order(6) @DisplayName("ACK 후 완료 기록 전 종료의 재발행 중복은 탐지·알림 기록을 중복 생성하지 않는다")
    void acknowledgedCrashAndDuplicateProcessing() throws Exception {
        String r=rid(); long id=fixture(r); assertThat(worker("ack-halt",r,40)).isEqualTo(25);
        assertThat(state(id)).isEqualTo("IN_FLIGHT"); assertThat(requestCount(id)).isEqualTo(1);
        assertThat(worker("publish",r,110)).isZero(); assertThat(requestCount(id)).isEqualTo(2);
        var c=new AiResultConsumer(JSON,threats);
        String result=JSON.writeValueAsString(Map.of("log_id",id,"threat_score",0.9,"ip_address","192.0.2.123","reason","isolated recovery fixture"));
        c.consume(result); c.consume(result);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detected_threats WHERE log_id=?",Integer.class,id)).isEqualTo(1);
        String key="request:"+r;
        assertThat(jdbc.queryForObject("SELECT revision FROM request_alerts WHERE alert_key=?",Long.class,key)).isEqualTo(1L);
        alerts.publish(key); alerts.publish(key);
        verify(messaging,times(1)).convertAndSend(eq("/topic/threats"),any(Object.class));
        evidence("ack_gap_duplicates",Map.of("logId",id,"broker_records",2,"threat_rows",1,"alert_revision",1,"server_send_calls",1,"transport","SimpMessagingTemplate mocked; live browser not verified"));
    }

    @Test @Order(7) @DisplayName("실제 DLT 전송 경로 장애 시 원본 offset을 전진시키지 않고 복구 후에만 커밋한다")
    void dltFailureDoesNotCommitSource() throws Exception {
        int port; try(var s=new ServerSocket(0)){port=s.getLocalPort();}
        var badPf=factory("127.0.0.1:"+port); var goodPf=factory(broker.getBrokersAsString());
        var cfg=new PipelineKafkaErrorConfig(); var recoverer=cfg.pipelineDltRecoverer(new KafkaTemplate<>(badPf));
        var handler=cfg.pipelineErrorHandler(recoverer); var failed=new CountDownLatch(1); var attempts=new AtomicInteger();
        handler.setRetryListeners(new RetryListener(){
            @Override public void failedDelivery(ConsumerRecord<?,?> record,Exception ex,int attempt){attempts.incrementAndGet();}
            @Override public void recoveryFailed(ConsumerRecord<?,?> record,Exception ex,Exception failure){failed.countDown();}
        });
        String group="recovery-"+rid();
        var props=new HashMap<String,Object>(); props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG,broker.getBrokersAsString());
        props.put(ConsumerConfig.GROUP_ID_CONFIG,group); props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG,"latest");
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG,false);
        var cf=new DefaultKafkaConsumerFactory<String,String>(props,new StringDeserializer(),new StringDeserializer());
        var f=new KafkaConsumerConfig().kafkaListenerContainerFactory(cf,handler);
        var container=f.createContainer("ai-result-topic"); var realConsumer=new AiResultConsumer(JSON,threats);
        container.getContainerProperties().setMessageListener((MessageListener<String,String>)record->realConsumer.consume(record.value()));
        container.start();
        try(var admin=Admin.create(Map.of("bootstrap.servers",broker.getBrokersAsString()))) {
            ContainerTestUtils.waitForAssignment(container,1);
            String value="{\"log_id\":9000000000012,\"threat_score\":0.1,\"ip_address\":\"0.0.0.0\",\"reason\":\"-\"}";
            var sent=new KafkaTemplate<>(goodPf).send("ai-result-topic","9000000000012",value).get(20,TimeUnit.SECONDS);
            var tp=new TopicPartition("ai-result-topic",sent.getRecordMetadata().partition()); long offset=sent.getRecordMetadata().offset();
            assertThat(failed.await(45,TimeUnit.SECONDS)).isTrue();
            var before=admin.listConsumerGroupOffsets(group).partitionsToOffsetAndMetadata().get(10,TimeUnit.SECONDS).get(tp);
            assertThat(before==null || before.offset()<=offset).isTrue();
            badPf.updateConfigs(Map.of(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,broker.getBrokersAsString())); badPf.reset();
            await(()->{try {var x=admin.listConsumerGroupOffsets(group).partitionsToOffsetAndMetadata().get(5,TimeUnit.SECONDS).get(tp);return x!=null && x.offset()>=offset+1;}catch(Exception e){return false;}},40);
            try(var reader=consumer()) {
                var dlt=new TopicPartition("ai-result-topic.DLT",0); reader.assign(List.of(dlt)); reader.seekToBeginning(List.of(dlt));
                boolean found=false; long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
                while(!found && System.nanoTime()<until) for(var row:reader.poll(Duration.ofMillis(200))) if(value.equals(row.value()))found=true;
                assertThat(found).isTrue();
            }
            evidence("dlt_offset_recovery",Map.of("source_offset",offset,"committed_before_recovery",before==null?-1:before.offset(),"committed_after_recovery",offset+1,"delivery_failures",attempts.get(),"dlt_present",true));
        } finally { container.stop(); badPf.destroy(); goodPf.destroy(); }
    }

    public static class Worker {
        public static void main(String[] args) throws Exception {
            try(var context=new AnnotationConfigApplicationContext(Config.class)) {
                String mode=args[0],id=args[1];
                var service=context.getBean(AiRequestOutboxService.class);
                if(mode.equals("enqueue-halt")) { context.getBean(LogService.class).processRawLog(message(id)); Runtime.getRuntime().halt(23); }
                if(mode.equals("claim-halt")) { if(service.claimNext().isEmpty())throw new IllegalStateException("No job");Runtime.getRuntime().halt(24); }
                var pf=factory(System.getenv("DG_RECOVERY_KAFKA"));
                var producer=new AiRequestProducer(new KafkaTemplate<>(pf),new SimpleMeterRegistry());
                if(mode.equals("ack-halt")) {var job=service.claimNext().orElseThrow();producer.sendStored(job.logId(),job.payload()).get(20,TimeUnit.SECONDS);Runtime.getRuntime().halt(25);}
                var publisher=new AiRequestOutboxPublisher(service,producer);
                try { await(()->publisher.publishNext(),90); } finally {pf.destroy();}
            }
        }
    }
}
