export const API_BASE_URL = (
    process.env.REACT_APP_API_BASE_URL || ''
).replace(/\/+$/,'');

export const WS_URL = 
    process.env.REACT_APP_WS_URL || '/ws-security';