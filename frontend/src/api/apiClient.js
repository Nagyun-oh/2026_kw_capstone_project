import axios from 'axios';
import {API_BASE_URL} from '../config';

const apiClient = axios.create({
    baseURL: API_BASE_URL,
    withCredentials: true,
    timeout: 10000,
})

const SAFE_METHODS = new Set(['get','head','options']);

// POST·PUT·PATCH·DELETE 등을 보내기 전에 CSRF 헤더 추가
apiClient.interceptors.request.use(async config =>{
    const method = (config.method|| 'get').toLowerCase();

    if(SAFE_METHODS.has(method)){
        return config;
    }

    const {data} = await apiClient.get('/api/v1/auth/csrf');

    if(!data.headerName || !data.token){
        throw new Error('CSRF 토큰을 가져오지 못했습니다.');
    }

    config.headers.set(data.headerName,data.token);

    return config;
});

export default apiClient;

/*

- apiClient.js: 쿠키·CSRF 공통 처리

    apiClient.get('/api/v1/logs')
    → 세션 쿠키를 포함해 바로 조회

    apiClient.post('/api/v1/auth/login', 입력값)
    → GET /api/v1/auth/csrf
    → 받은 토큰을 요청 헤더에 추가
    → POST /api/v1/auth/login
*/