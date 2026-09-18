import {
  initializeAppCheck,
  ReCaptchaEnterpriseProvider
} from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-app-check.js';
import { appCheckConfig } from './app-check-config.js';

export async function initAppCheck(app){
  const siteKey=String(appCheckConfig?.siteKey||'').trim();
  if(!siteKey){
    window.__LPS_APP_CHECK_STATUS__='pending_configuration';
    console.info('[LPS App Check] Integração pronta; chave reCAPTCHA Enterprise ainda não configurada.');
    return null;
  }
  try{
    const appCheck=initializeAppCheck(app,{
      provider:new ReCaptchaEnterpriseProvider(siteKey),
      isTokenAutoRefreshEnabled:true
    });
    window.__LPS_APP_CHECK_STATUS__='active';
    return appCheck;
  }catch(error){
    window.__LPS_APP_CHECK_STATUS__='error';
    console.error('[LPS App Check] Falha ao inicializar:',error?.message||error);
    throw error;
  }
}
