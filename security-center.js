import { getApps } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js';
import {
  getAuth, onAuthStateChanged, signOut, signInWithEmailAndPassword,
  getMultiFactorResolver, multiFactor, TotpMultiFactorGenerator
} from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js';
import { getFirestore, doc, getDoc } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js';

const SECURITY_ENDPOINT='https://membyrbgynicllzrhjsl.supabase.co/functions/v1/lps-iam-security';
const IDLE_MS=20*60*1000;
const SESSION_MAX_MS=8*60*60*1000;
const LOGIN_WINDOW_MS=10*60*1000;
const LOGIN_LOCK_MS=60*1000;
const LOGIN_MAX_FAILURES=5;
const DEVICE_SECRET_KEY='lps.cc.device.secret.v1';
const LOGIN_GUARD_KEY='lps.cc.login.guard.v1';

const $=id=>document.getElementById(id);
let auth=null;
let db=null;
let currentUser=null;
let currentPerson=null;
let currentDeviceId='';
let pendingTotpSecret=null;
let pendingResolver=null;
let pendingHint=null;
let lastActivity=Date.now();
let idleTimer=null;
let sessionTimer=null;
let sessionLoginLogged=false;

const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const fmtDate=value=>{try{return value?new Date(value).toLocaleString('pt-BR'):'—';}catch{return '—';}};
const setText=(id,value)=>{const el=$(id);if(el)el.textContent=String(value??'—');};
const show=(id,on=true)=>$(id)?.classList.toggle('hidden',!on);

async function waitForFirebaseApp(){
  for(let i=0;i<100;i++){
    const app=getApps()[0];
    if(app) return app;
    await sleep(50);
  }
  throw new Error('Firebase app não inicializado.');
}

function ensureUi(){
  if($('securityNav')) return;
  const nav=document.querySelector('.sidebar nav');
  const button=document.createElement('button');
  button.id='securityNav';
  button.className='nav hidden';
  button.dataset.view='security';
  button.textContent='Security Center';
  nav?.appendChild(button);

  const main=document.querySelector('.main');
  const section=document.createElement('section');
  section.id='view-security';
  section.className='view';
  section.innerHTML=`
    <div class="section-head"><div><h2>Security Center</h2><p class="muted">Sessão, MFA, dispositivos reconhecidos e sinais de acesso.</p></div><button id="securityRefresh" class="btn">Atualizar</button></div>
    <div class="security-grid">
      <article class="security-card"><span>MFA</span><strong id="securityMfa">Verificando…</strong><small id="securityMfaDetail">—</small><button id="securityMfaSetup" class="btn primary hidden" type="button">Ativar autenticador</button></article>
      <article class="security-card"><span>Sessão</span><strong id="securitySession">Ativa</strong><small id="securitySessionDetail">Timeout por inatividade: 20 min</small><button id="securitySignOut" class="btn" type="button">Encerrar sessão</button></article>
      <article class="security-card"><span>Dispositivo atual</span><strong id="securityDevice">Registrando…</strong><small id="securityDeviceDetail">—</small></article>
      <article class="security-card"><span>IAM</span><strong id="securityIam">Protegido</strong><small>Rate limiting + token Firebase + autorização por papel</small></article>
    </div>
    <div class="security-panel"><div class="section-head"><div><h3>Dispositivos reconhecidos</h3><p class="muted">Reconhecimento serve para auditoria. Não substitui MFA.</p></div></div><div id="securityDevices" class="security-list"><div class="empty">Carregando…</div></div></div>
    <div id="securityAdminPanel" class="security-panel hidden"><div class="section-head"><div><h3>Sinais de segurança · últimas 24h</h3><p class="muted">Acessos negados, limites acionados, dispositivos novos e política MFA.</p></div></div><div id="securityStats" class="security-stats"></div><div id="securityEvents" class="security-list"></div></div>
  `;
  main?.appendChild(section);

  const mfaDialog=document.createElement('dialog');
  mfaDialog.id='mfaSetupDialog';
  mfaDialog.innerHTML=`<form class="dialog-form" method="dialog"><h2>Ativar MFA por autenticador</h2><p class="muted">No Google Authenticator, Microsoft Authenticator ou app compatível, escolha adicionar chave manual.</p><label>Chave secreta<input id="mfaSecretKey" readonly></label><button id="mfaCopySecret" class="btn" type="button">Copiar chave</button><label>Código de 6 dígitos<input id="mfaEnrollCode" inputmode="numeric" autocomplete="one-time-code" maxlength="8" placeholder="000000"></label><p id="mfaEnrollStatus" class="status"></p><div class="actions"><button id="mfaCancel" class="btn" type="button">Cancelar</button><button id="mfaConfirm" class="btn primary" type="button">Confirmar MFA</button></div></form>`;
  document.body.appendChild(mfaDialog);

  const challengeDialog=document.createElement('dialog');
  challengeDialog.id='mfaChallengeDialog';
  challengeDialog.innerHTML=`<form class="dialog-form" method="dialog"><h2>Verificação em duas etapas</h2><p class="muted">Informe o código do seu aplicativo autenticador para concluir o acesso.</p><label>Código<input id="mfaLoginCode" inputmode="numeric" autocomplete="one-time-code" maxlength="8" placeholder="000000"></label><p id="mfaLoginStatus" class="status"></p><div class="actions"><button id="mfaLoginCancel" class="btn" type="button">Cancelar</button><button id="mfaLoginConfirm" class="btn primary" type="button">Verificar</button></div></form>`;
  document.body.appendChild(challengeDialog);

  button.addEventListener('click',activateSecurityView);
  $('securityRefresh')?.addEventListener('click',refreshSecurity);
  $('securitySignOut')?.addEventListener('click',()=>auth&&signOut(auth));
  $('securityMfaSetup')?.addEventListener('click',startMfaEnrollment);
  $('mfaCopySecret')?.addEventListener('click',async()=>{const v=$('mfaSecretKey')?.value||'';if(v)await navigator.clipboard?.writeText(v);});
  $('mfaCancel')?.addEventListener('click',()=>{pendingTotpSecret=null;$('mfaSetupDialog')?.close();});
  $('mfaConfirm')?.addEventListener('click',confirmMfaEnrollment);
  $('mfaLoginCancel')?.addEventListener('click',()=>{pendingResolver=null;pendingHint=null;$('mfaChallengeDialog')?.close();});
  $('mfaLoginConfirm')?.addEventListener('click',completeMfaSignIn);
}

function activateSecurityView(){
  if(!currentUser) return;
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.nav').forEach(v=>v.classList.remove('active'));
  $('view-security')?.classList.add('active');
  $('securityNav')?.classList.add('active');
  setText('viewTitle','Security Center');
  refreshSecurity();
}

function activity(){lastActivity=Date.now();}
function startSessionProtection(){
  ['pointerdown','keydown','touchstart','scroll'].forEach(name=>window.addEventListener(name,activity,{passive:true}));
  clearInterval(idleTimer); clearInterval(sessionTimer);
  idleTimer=setInterval(async()=>{
    if(currentUser && Date.now()-lastActivity>IDLE_MS){
      await securityApi('security_event',{event:'session_timeout',note:'20 minutos de inatividade'}).catch(()=>{});
      await signOut(auth).catch(()=>{});
    }
  },30000);
  sessionTimer=setInterval(async()=>{
    if(!currentUser) return;
    const authTime=Date.parse(currentUser.metadata?.lastSignInTime||'');
    if(Number.isFinite(authTime)&&Date.now()-authTime>SESSION_MAX_MS){
      await securityApi('security_event',{event:'session_timeout',note:'sessão acima de 8 horas'}).catch(()=>{});
      await signOut(auth).catch(()=>{});
    }
  },60000);
}

function getLoginGuard(){
  try{return JSON.parse(localStorage.getItem(LOGIN_GUARD_KEY)||'{"failures":[],"lockedUntil":0}');}catch{return {failures:[],lockedUntil:0};}
}
function saveLoginGuard(data){localStorage.setItem(LOGIN_GUARD_KEY,JSON.stringify(data));}
function loginLockRemaining(){const g=getLoginGuard();return Math.max(0,Number(g.lockedUntil||0)-Date.now());}
function recordLoginFailure(){
  const now=Date.now(); const g=getLoginGuard();
  const failures=(Array.isArray(g.failures)?g.failures:[]).filter(t=>now-Number(t)<LOGIN_WINDOW_MS); failures.push(now);
  const lockedUntil=failures.length>=LOGIN_MAX_FAILURES?now+LOGIN_LOCK_MS:0;
  saveLoginGuard({failures,lockedUntil}); return {count:failures.length,lockedUntil};
}
function clearLoginGuard(){localStorage.removeItem(LOGIN_GUARD_KEY);}

function installSecureLoginHandlers(){
  const form=$('emailForm');
  if(form&&!form.dataset.securityBound){
    form.dataset.securityBound='1';
    form.addEventListener('submit',async event=>{
      event.preventDefault(); event.stopImmediatePropagation();
      const remaining=loginLockRemaining();
      if(remaining>0){setText('loginStatus',`Aguarde ${Math.ceil(remaining/1000)}s antes de tentar novamente.`);return;}
      const email=String($('email')?.value||'').trim().toLowerCase(); const password=String($('password')?.value||'');
      if(!email||!password) return;
      setText('loginStatus','Validando acesso…');
      try{
        await signInWithEmailAndPassword(auth,email,password); clearLoginGuard(); setText('loginStatus','');
      }catch(err){
        if(err?.code==='auth/multi-factor-auth-required'){
          try{
            pendingResolver=getMultiFactorResolver(auth,err);
            pendingHint=pendingResolver.hints.find(h=>h.factorId===TotpMultiFactorGenerator.FACTOR_ID)||pendingResolver.hints[0]||null;
            if(!pendingHint) throw new Error('SECOND_FACTOR_UNAVAILABLE');
            setText('mfaLoginStatus',''); $('mfaLoginCode').value=''; $('mfaChallengeDialog')?.showModal(); setText('loginStatus','Verificação adicional necessária.');
            return;
          }catch{setText('loginStatus','Não foi possível iniciar a verificação em duas etapas.');return;}
        }
        const g=recordLoginFailure();
        if(err?.code==='auth/too-many-requests'||g.lockedUntil){setText('loginStatus','Muitas tentativas. Aguarde 60 segundos e tente novamente.');}
        else setText('loginStatus','Não foi possível autenticar. Verifique suas credenciais.');
      }
    },true);
  }

  const reset=$('resetPassword');
  if(reset&&!reset.dataset.securityBound){
    reset.dataset.securityBound='1';
    reset.addEventListener('click',event=>{
      event.preventDefault(); event.stopImmediatePropagation();
      setText('loginStatus','Se a conta estiver cadastrada, as instruções de redefinição serão enviadas.');
    },true);
  }
}

async function completeMfaSignIn(){
  const code=String($('mfaLoginCode')?.value||'').replace(/\D/g,'');
  if(!pendingResolver||!pendingHint||code.length<6) return setText('mfaLoginStatus','Informe o código do autenticador.');
  try{
    setText('mfaLoginStatus','Verificando…');
    const assertion=TotpMultiFactorGenerator.assertionForSignIn(pendingHint.uid,code);
    await pendingResolver.resolveSignIn(assertion);
    pendingResolver=null; pendingHint=null; clearLoginGuard(); $('mfaChallengeDialog')?.close(); setText('loginStatus','');
  }catch{setText('mfaLoginStatus','Código inválido ou expirado.');}
}

async function startMfaEnrollment(){
  if(!currentUser) return;
  try{
    setText('securityMfaDetail','Preparando chave TOTP…');
    const session=await multiFactor(currentUser).getSession();
    pendingTotpSecret=await TotpMultiFactorGenerator.generateSecret(session);
    $('mfaSecretKey').value=pendingTotpSecret.secretKey||'';
    $('mfaEnrollCode').value=''; setText('mfaEnrollStatus',''); $('mfaSetupDialog')?.showModal();
    setText('securityMfaDetail','Finalize a configuração no autenticador.');
  }catch(err){
    const code=String(err?.code||'');
    setText('securityMfaDetail',code==='auth/operation-not-allowed'?'TOTP precisa ser habilitado no Firebase Authentication.':'Não foi possível iniciar o MFA. Faça login novamente e tente de novo.');
  }
}

async function confirmMfaEnrollment(){
  if(!currentUser||!pendingTotpSecret) return;
  const code=String($('mfaEnrollCode')?.value||'').replace(/\D/g,'');
  if(code.length<6) return setText('mfaEnrollStatus','Informe o código gerado pelo autenticador.');
  try{
    setText('mfaEnrollStatus','Ativando…');
    const assertion=TotpMultiFactorGenerator.assertionForEnrollment(pendingTotpSecret,code);
    await multiFactor(currentUser).enroll(assertion,'LPS Authenticator');
    await securityApi('security_event',{event:'mfa_enrolled',note:'TOTP cadastrado'}).catch(()=>{});
    pendingTotpSecret=null; $('mfaSetupDialog')?.close();
    setText('securityMfa','Ativo'); setText('securityMfaDetail','MFA cadastrado. Entre novamente para validar o segundo fator e ativar a política administrativa.');
    show('securityMfaSetup',false);
    setTimeout(()=>signOut(auth).catch(()=>{}),1200);
  }catch{setText('mfaEnrollStatus','Não foi possível validar o código. Gere um novo código e tente novamente.');}
}

async function securityApi(action,payload={}){
  if(!currentUser) throw new Error('NO_SESSION');
  const token=await currentUser.getIdToken(false);
  const response=await fetch(SECURITY_ENDPOINT,{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${token}`},body:JSON.stringify({action,...payload}),cache:'no-store'});
  const data=await response.json().catch(()=>({}));
  if(response.status===401&&data?.error==='SESSION_EXPIRED'){await signOut(auth).catch(()=>{});}
  if(!response.ok) throw new Error(data?.error||`HTTP_${response.status}`);
  return data;
}

async function deviceId(){
  let secret=localStorage.getItem(DEVICE_SECRET_KEY);
  if(!secret){const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);secret=Array.from(bytes).map(v=>v.toString(16).padStart(2,'0')).join('');localStorage.setItem(DEVICE_SECRET_KEY,secret);}
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(secret));
  return Array.from(new Uint8Array(digest)).map(v=>v.toString(16).padStart(2,'0')).join('');
}

async function registerCurrentDevice(){
  currentDeviceId=await deviceId();
  const label=[navigator.platform||'',navigator.userAgentData?.mobile?'Mobile':'Web'].filter(Boolean).join(' · ')||'Navegador';
  const result=await securityApi('register_device',{deviceId:currentDeviceId,label,userAgent:navigator.userAgent});
  setText('securityDevice',result.revoked?'Revogado':result.isNew?'Novo dispositivo':'Reconhecido');
  setText('securityDeviceDetail',`${label} · ${currentDeviceId.slice(0,12)}…`);
  if(result.revoked){setText('securityDeviceDetail','Este dispositivo foi revogado. A sessão será encerrada.');setTimeout(()=>signOut(auth).catch(()=>{}),800);}
  return result;
}

async function renderMfa(){
  if(!currentUser) return;
  const factors=multiFactor(currentUser).enrolledFactors||[];
  if(factors.length){setText('securityMfa','Ativo');setText('securityMfaDetail',`${factors.length} fator(es) cadastrado(s).`);show('securityMfaSetup',false);}
  else{setText('securityMfa','Não configurado');setText('securityMfaDetail','Recomendado para contas administrativas.');show('securityMfaSetup',true);}
}

function renderDevices(devices=[]){
  const box=$('securityDevices'); if(!box) return; box.replaceChildren();
  if(!devices.length){const e=document.createElement('div');e.className='empty';e.textContent='Nenhum dispositivo registrado.';box.appendChild(e);return;}
  for(const d of devices){
    const row=document.createElement('div'); row.className='security-row';
    const info=document.createElement('div');
    const title=document.createElement('strong'); title.textContent=`${d.label||'Dispositivo'}${d.device_id===currentDeviceId?' · atual':''}`;
    const meta=document.createElement('span'); meta.textContent=`Último acesso ${fmtDate(d.last_seen)} · ${d.revoked_at?'revogado':'ativo'}`;
    info.append(title,meta); row.appendChild(info);
    if(!d.revoked_at){const b=document.createElement('button');b.className='btn';b.type='button';b.textContent='Revogar';b.addEventListener('click',async()=>{if(!confirm('Revogar este dispositivo reconhecido?'))return;await securityApi('revoke_device',{deviceId:d.device_id});if(d.device_id===currentDeviceId)await signOut(auth);else await refreshSecurity();});row.appendChild(b);}
    box.appendChild(row);
  }
}

function renderSummary(data){
  const c=data?.counts||{}; const stats=$('securityStats'); if(stats){stats.replaceChildren();
    const items=[['Usuários ativos',c.activeUsers],['Acessos negados',c.accessDenied],['Rate limits',c.rateLimited],['Novos dispositivos',c.newDevices],['Dispositivos revogados',c.revokedDevices],['Admins com MFA obrigatório',c.mfaProtectedAdmins]];
    for(const [label,value] of items){const card=document.createElement('article');const s=document.createElement('span');s.textContent=label;const strong=document.createElement('strong');strong.textContent=String(value??0);card.append(s,strong);stats.appendChild(card);}
  }
  const events=$('securityEvents'); if(events){events.replaceChildren(); const rows=data?.events||[]; if(!rows.length){const e=document.createElement('div');e.className='empty';e.textContent='Nenhum sinal relevante nas últimas 24 horas.';events.appendChild(e);}else for(const x of rows){const row=document.createElement('div');row.className='security-row';const info=document.createElement('div');const title=document.createElement('strong');title.textContent=x.action||'evento';const meta=document.createElement('span');meta.textContent=`${fmtDate(x.created_at)} · ${x.actor_email||'origem não autenticada'} · ${x.project_id||'IAM'}`;info.append(title,meta);row.appendChild(info);events.appendChild(row);}}
}

async function refreshSecurity(){
  if(!currentUser) return;
  try{
    await renderMfa();
    const registration=await registerCurrentDevice();
    const list=await securityApi('list_devices'); renderDevices(list.devices||[]);
    if(currentPerson?.globalRole==='super_admin'){
      show('securityAdminPanel',true);
      const summary=await securityApi('security_summary'); renderSummary(summary);
      setText('securityIam',summary.mfaRequired?'MFA obrigatório':'Proteção ativa');
      if(summary.mfaRequired&&!summary.secondFactor){setText('securityIam','MFA pendente');}
    }else show('securityAdminPanel',false);
    if(registration?.secondFactor) await securityApi('security_event',{event:'mfa_verified',note:'sessão autenticada com segundo fator'}).catch(()=>{});
  }catch(err){setText('securityIam',`Indisponível (${String(err?.message||err)})`);}
}

async function loadPerson(user){
  if(!user?.email) return null;
  const snap=await getDoc(doc(db,'people',String(user.email).trim().toLowerCase()));
  return snap.exists()?snap.data():null;
}

async function init(){
  ensureUi();
  const app=await waitForFirebaseApp(); auth=getAuth(app); db=getFirestore(app);
  installSecureLoginHandlers(); startSessionProtection();
  onAuthStateChanged(auth,async user=>{
    currentUser=user; currentPerson=null; sessionLoginLogged=false;
    if(!user){show('securityNav',false);return;}
    try{
      currentPerson=await loadPerson(user);
      if(!currentPerson?.active) return;
      show('securityNav',true); lastActivity=Date.now();
      const authTime=Date.parse(user.metadata?.lastSignInTime||'');
      setText('securitySession','Ativa'); setText('securitySessionDetail',`Login: ${fmtDate(user.metadata?.lastSignInTime)} · timeout 20 min · máximo local 8h`);
      await registerCurrentDevice().catch(()=>{});
      await renderMfa();
      if(!sessionLoginLogged){sessionLoginLogged=true;await securityApi('security_event',{event:'session_login',note:'sessão iniciada'}).catch(()=>{});}
      if(Number.isFinite(authTime)&&Date.now()-authTime>SESSION_MAX_MS) await signOut(auth);
    }catch(err){console.warn('[LPS Security Center]',err?.message||err);}
  });
}

init().catch(err=>console.error('[LPS Security Center] init',err));
