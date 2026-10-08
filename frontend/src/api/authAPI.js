import apiClient from './apiClient';

// 로그인 성공 시 {username,role} 반환
export async function loginAdmin({username,password}){
    const response = await apiClient.post('/api/v1/auth/login',{
        username,
        password,
    });

    return response.data;
}

// 현재 로그인한 관리자 조회
export async function getCurrentAdmin() {
    const response = await apiClient.get('/api/v1/auth/me');

    return response.data;
}

// 로그아웃: 성공 응답은 204이므로 반환 데이터는 없음
export async function logoutAdmin(){
    await apiClient.post('/api/v1/auth/logout');
}

/*
 - authAPI.js: 백엔드 인증 API 호출
*/