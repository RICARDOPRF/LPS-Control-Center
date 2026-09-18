import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js';
import {
  getAuth, signInWithEmailAndPassword, sendPasswordResetEmail, signOut,
  setPersistence, browserLocalPersistence, onAuthStateChanged
} from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js';
import {
  getFirestore, doc, getDoc, getDocs, setDoc, deleteDoc, collection,
  addDoc, serverTimestamp, query, orderBy, limit, onSnapshot
} from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js';
import { firebaseConfig } from './firebase-config.js';
import { initAppCheck } from './app-check.js';

const $ = id => document.getElementById(id);
const ROLE_LABEL = {
  viewer: 'Visualizador', operator: 'Operador', planner: 'Planejamento',
  project_admin: 'Administrador de obra', super_admin: 'Admin LPS'
};
const PERMISSIONS = [
  ['view','Visualizar'], ['edit','Editar'], ['progress','Lançar avanço'],
  ['import','Importar'], ['export','Exportar'], ['config','Configuração'],
  ['users','Usuários'], ['admin','Admin da obra']
];
const IAM_ADMIN_ENDPOINT = 'https://membyrbgynicllzrhjsl.supabase.co/functions/v1/lps-iam-admin';
const state = { authUser:null, person:null, projects:[], visibleProjects:[], people:[], auth:null, db:null, personUnsubscribe:null };\nconst REVOCATION_REASON_KEY = 'lps.cc.revocation.reason';

const normalizeEmail = value => String(value || '').trim().toLowerCase();
const esc = value => String(value ?? '').replace(/[&<>'\"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','\"':'&quot;'}[c]));
const slug = value => String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'');

function showOnly(id){ ['boot','login','blocked','app'].forEach(x=>$(x)?.classList.add('hidden')); $(id)?.classList.remove('hidden'); }
function setStatus(text=''){ if($('loginStatus')) $('loginStatus').textContent = text; }
function setBlocked(text){ if($('blockedText')) $('blockedText').textContent = text; showOnly('blocked'); }
function isSuper(){ return state.person?.active === true && state.person?.globalRole === 'super_admin'; }
function can(projectId, permission='view'){
  if(isSuper()) return true;
  return state.person?.active === true && state.person?.projects?.[projectId]?.[permission] === true;
}
function adminUI(){ document.querySelectorAll('.admin-only').forEach(el=>el.classList.toggle('hidden', !isSuper())); }

async function iamAdmin(action,payload={}){
  if(!state.authUser) throw new Error('Sessão administrativa ausente.');
  const token=await state.authUser.getIdToken(false);
  const response=await fetch(IAM_ADMIN_ENDPOINT,{
    method:'POST',
    headers:{'Content-Type':'application/json',Authorization:`Bearer ${token}`},
    body:JSON.stringify({action,...payload}),
    cache:'no-store'
  });
  const data=await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(data?.message||data?.error||'Falha no IAM central.');
  return data;
}

async function currentPerson(user){
  if(!user?.email || !state.db) return null;
  const snap = await getDoc(doc(state.db,'people',normalizeEmail(user.email)));
  return snap.exists() ? {id:snap.id,...snap.data()} : null;
}

function stopPersonWatch(){
  if(typeof state.personUnsubscribe==='function'){
    try{state.personUnsubscribe();}catch{}
  }
  state.personUnsubscribe=null;
}

async function revokeLocalSession(reason){
  stopPersonWatch();
  try{sessionStorage.setItem(REVOCATION_REASON_KEY,String(reason||'Sua sessão foi revogada.'));}catch{}
  try{await signOut(state.auth);}catch{}
}

function startPersonWatch(user){
  stopPersonWatch();
  if(!user?.email || !state.db) return;
  const email=normalizeEmail(user.email);
  state.personUnsubscribe=onSnapshot(doc(state.db,'people',email),snap=>{
    const person=snap.exists()?{id:snap.id,...snap.data()}:null;
    if(!person || person.active!==true){
      revokeLocalSession('Seu acesso ao LPS Control Center foi revogado. Entre novamente somente após nova liberação.');
      return;
    }
    const roleChanged=state.person?.globalRole!==person.globalRole;
    const permissionsChanged=JSON.stringify(state.person?.projects||{})!==JSON.stringify(person.projects||{});
    state.person=person;
    adminUI();
    renderUser();
    if(!isSuper() && (document.querySelector('#view-people.active')||document.querySelector('#view-audit.active'))) switchView('dashboard');
    if(roleChanged||permissionsChanged) loadProjects().catch(err=>console.warn('Atualização de permissões:',err?.message||err));
  },error=>{
    console.warn('Monitor de autorização em tempo real:',error?.code||error?.message||error);
    revokeLocalSession('Não foi possível revalidar sua autorização. A sessão foi encerrada por segurança.');
  });
}

async function audit(action, details='', projectId=null){
  try{
    if(!state.db || !state.authUser || !state.person?.active) return;
    await addDoc(collection(state.db,'audit'),{
      action, details:String(details||'').slice(0,500), projectId:projectId||null,
      actorUid:state.authUser.uid, actorEmail:normalizeEmail(state.authUser.email),
      actorName:state.person.name || state.authUser.displayName || '', createdAt:serverTimestamp()
    });
  }catch(err){ console.warn('Audit:',err?.code||err?.message||err); }
}

function renderUser(){
  $('currentUser').innerHTML = `<strong>${esc(state.person?.name || state.authUser?.displayName || 'Usuário')}</strong><br>${esc(state.authUser?.email||'')}`;
  const role = ROLE_LABEL[state.person?.globalRole] || state.person?.globalRole || 'Usuário';
  $('roleBadge').textContent = role;
  $('statRole').textContent = role;
}

async function loadProjects(){
  state.projects=[]; state.visibleProjects=[];
  if(isSuper()){
    const snap=await getDocs(collection(state.db,'projects'));
    state.projects=snap.docs.map(d=>({id:d.id,...d.data()})).sort((a,b)=>String(a.name||a.id).localeCompare(String(b.name||b.id),'pt-BR'));
    state.visibleProjects=state.projects.filter(p=>p.active!==false);
  }else{
    const ids=Object.entries(state.person?.projects||{}).filter(([,p])=>p?.view===true).map(([id])=>id);
    for(const id of ids){ const s=await getDoc(doc(state.db,'projects',id)); if(s.exists()) state.projects.push({id:s.id,...s.data()}); }
    state.visibleProjects=state.projects.filter(p=>p.active!==false && can(p.id,'view'));
  }
  renderProjects();
}

function card(project, adminMode=false){
  const open = project.appUrl && can(project.id,'view')
    ? `<button class="btn primary js-open" data-id="${esc(project.id)}">Abrir</button>`
    : `<button class="btn" disabled>${project.appUrl?'Sem permissão':'Sem URL'}</button>`;
  const edit = adminMode && isSuper() ? `<button class="btn js-edit-project" data-id="${esc(project.id)}">Editar</button>` : '';
  return `<article class="project-card"><div><h3>${esc(project.name||project.id)}</h3><div class="chips"><span class="chip">${esc(project.category||'Projeto')}</span><span class="chip ${project.visibility==='private'?'private':''}">${esc(project.visibility||'—')}</span></div></div><div class="muted">${esc(project.repo||'')}</div><div class="project-actions">${open}${edit}</div></article>`;
}

function renderProjects(){
  $('statProjects').textContent=state.visibleProjects.length;
  $('statPanels').textContent=state.visibleProjects.filter(p=>p.category==='Painel de Bordo').length;
  $('dashboardProjects').innerHTML=state.visibleProjects.length?state.visibleProjects.map(p=>card(p)).join(''):'<div class="empty">Nenhum projeto liberado para esta conta.</div>';
  const list=isSuper()?state.projects:state.visibleProjects;
  $('projects').innerHTML=list.length?list.map(p=>card(p,true)).join(''):'<div class="empty">Nenhum projeto cadastrado.</div>';
  document.querySelectorAll('.js-open').forEach(btn=>btn.addEventListener('click',async()=>{
    const p=state.projects.find(x=>x.id===btn.dataset.id); if(!p||!p.appUrl||!can(p.id,'view')) return;
    await audit('project_open',p.name||p.id,p.id); window.open(p.appUrl,'_blank','noopener,noreferrer');
  }));
  document.querySelectorAll('.js-edit-project').forEach(btn=>btn.addEventListener('click',()=>openProject(btn.dataset.id)));
}

async function loadPeople(){
  if(!isSuper()) return;
  const snap=await getDocs(collection(state.db,'people'));
  state.people=snap.docs.map(d=>({id:d.id,...d.data()})).sort((a,b)=>String(a.name||a.email).localeCompare(String(b.name||b.email),'pt-BR'));
  $('peopleBody').innerHTML=state.people.length?state.people.map(p=>`<tr><td>${esc(p.name||'—')}</td><td>${esc(p.email||p.id)}</td><td>${esc(p.company||'—')}</td><td>${esc(ROLE_LABEL[p.globalRole]||p.globalRole||'—')}</td><td><span class="status-dot ${p.active===false?'off':''}">${p.active===false?'Bloqueado':'Ativo'}</span></td><td><button class="btn js-edit-person" data-email="${esc(p.id)}">Editar</button></td></tr>`).join(''):'<tr><td colspan="6">Nenhuma pessoa cadastrada.</td></tr>';
  document.querySelectorAll('.js-edit-person').forEach(btn=>btn.addEventListener('click',()=>openPerson(btn.dataset.email)));
}

async function loadAudit(){
  if(!isSuper()) return;
  try{
    const snap=await getDocs(query(collection(state.db,'audit'),orderBy('createdAt','desc'),limit(100)));
    const rows=snap.docs.map(d=>d.data());
    $('auditList').innerHTML=rows.length?rows.map(x=>`<div class="audit-item"><strong>${esc(x.action||'evento')} — ${esc(x.actorName||x.actorEmail||'')}</strong><span>${esc(x.createdAt?.toDate?x.createdAt.toDate().toLocaleString('pt-BR'):'agora')} · ${esc(x.projectId||'Control Center')}</span><div>${esc(x.details||'')}</div></div>`).join(''):'<div class="empty">Sem eventos.</div>';
  }catch(err){ $('auditList').innerHTML=`<div class="empty">Auditoria indisponível: ${esc(err?.message||err)}</div>`; }
}

function openProject(id=null){
  if(!isSuper()) return;
  const p=id?state.projects.find(x=>x.id===id):null;
  $('projectOriginal').value=p?.id||''; $('projectName').value=p?.name||''; $('projectId').value=p?.id||''; $('projectId').disabled=!!p;
  $('projectCategory').value=p?.category||'Painel de Bordo'; $('projectRepo').value=p?.repo||''; $('projectUrl').value=p?.appUrl||''; $('projectActive').checked=p?.active!==false;
  $('projectDialog').showModal();
}

async function saveProject(event){
  event.preventDefault(); if(!isSuper()) return;
  const original=$('projectOriginal').value; const id=original||slug($('projectId').value||$('projectName').value); if(!id) return;
  const repo=$('projectRepo').value.trim(); const existing=state.projects.find(x=>x.id===original);
  const payload={name:$('projectName').value.trim(),category:$('projectCategory').value,repo,repoUrl:repo?`https://github.com/${repo}`:'',appUrl:$('projectUrl').value.trim(),active:$('projectActive').checked,visibility:existing?.visibility||'private',updatedAt:serverTimestamp(),updatedBy:normalizeEmail(state.authUser.email)};
  if(!original) payload.createdAt=serverTimestamp();
  await setDoc(doc(state.db,'projects',id),payload,{merge:true});
  await iamAdmin('sync_project',{project:{id,name:payload.name,category:payload.category,repo:payload.repo,appUrl:payload.appUrl,active:payload.active}});
  await audit('project_saved',payload.name||id,id); $('projectDialog').close(); await loadProjects();
}

function permissionHtml(person=null){
  return state.projects.map(p=>{
    const cur=person?.projects?.[p.id]||{};
    return `<div class="permission-row"><div class="permission-head"><strong>${esc(p.name||p.id)}</strong><span class="muted">${esc(p.id)}</span></div><div class="permission-grid">${PERMISSIONS.map(([key,label])=>`<label><input type="checkbox" data-project="${esc(p.id)}" data-permission="${key}" ${cur[key]===true?'checked':''}>${esc(label)}</label>`).join('')}</div></div>`;
  }).join('')||'<div class="empty">Cadastre projetos primeiro.</div>';
}

function openPerson(email=null){
  if(!isSuper()) return;
  const p=email?state.people.find(x=>x.id===email):null;
  $('personOriginal').value=p?.id||''; $('personName').value=p?.name||''; $('personEmail').value=p?.email||p?.id||''; $('personEmail').disabled=!!p;
  $('personCompany').value=p?.company||''; $('personRole').value=p?.globalRole||'viewer'; $('personActive').checked=p?.active!==false;
  $('personPassword').value=''; $('personPassword').required=!p; $('personPasswordWrap').classList.toggle('hidden',!!p);
  $('permissionEditor').innerHTML=permissionHtml(p); $('personDialog').showModal();
}

function collectPermissions(){
  const projects={};
  document.querySelectorAll('#permissionEditor input[data-project][data-permission]').forEach(input=>{
    projects[input.dataset.project] ||= {}; projects[input.dataset.project][input.dataset.permission]=input.checked;
  });
  return projects;
}

async function savePerson(event){
  event.preventDefault(); if(!isSuper()) return;
  const original=$('personOriginal').value; const email=normalizeEmail($('personEmail').value); if(!email) return;
  const permissions=collectPermissions();
  const payload={name:$('personName').value.trim(),email,company:$('personCompany').value.trim(),globalRole:$('personRole').value,active:$('personActive').checked,projects:permissions,updatedAt:serverTimestamp(),updatedBy:normalizeEmail(state.authUser.email)};
  if(!original) payload.createdAt=serverTimestamp();
  const grants=Object.entries(permissions).map(([projectId,perms])=>{
    const p=state.projects.find(x=>x.id===projectId)||{};
    return {projectId,projectName:p.name||projectId,category:p.category||'Projeto',repo:p.repo||'',appUrl:p.appUrl||'',role:payload.globalRole,permissions:perms,active:payload.active};
  });
  const iam=await iamAdmin(original?'upsert_person':'provision_user',{
    person:{name:payload.name,email,company:payload.company,globalRole:payload.globalRole,active:payload.active},
    password:$('personPassword').value,
    grants
  });
  if(!original && Array.isArray(iam.provisionResults)){
    const failures=iam.provisionResults.filter(x=>x.status==='error');
    if(failures.length) throw new Error('Cadastro parcial. Falha de credencial em: '+failures.map(x=>x.projectId).join(', '));
  }
  await setDoc(doc(state.db,'people',email),payload,{merge:true}); if(original&&original!==email) await deleteDoc(doc(state.db,'people',original));
  await audit('person_permissions_saved',email); $('personDialog').close(); await loadPeople();
}

async function importSeed(){
  if(!isSuper()) return;
  const r=await fetch('./projects.seed.json',{cache:'no-store'}); if(!r.ok) throw new Error('projects.seed.json indisponível');
  const seed=await r.json(); let count=0;
  for(const item of seed.projects||[]){
    const ref=doc(state.db,'projects',item.id); const existing=await getDoc(ref); if(existing.exists()) continue;
    await setDoc(ref,{...item,createdAt:serverTimestamp(),updatedAt:serverTimestamp(),updatedBy:normalizeEmail(state.authUser.email)});
    await iamAdmin('sync_project',{project:{id:item.id,name:item.name||item.id,category:item.category||'Projeto',repo:item.repo||'',appUrl:item.appUrl||'',active:item.active!==false}});
    count++;
  }
  await audit('github_seed_imported',`${count} projetos importados`); await loadProjects(); alert(`${count} projeto(s) novo(s) importado(s).`);
}

function switchView(name){
  if((name==='people'||name==='audit')&&!isSuper()) return;
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active')); $(`view-${name}`)?.classList.add('active');
  document.querySelectorAll('.nav').forEach(b=>b.classList.toggle('active',b.dataset.view===name));
  const titles={dashboard:'Visão geral',projects:'Projetos',people:'Pessoas e permissões',audit:'Auditoria'}; $('viewTitle').textContent=titles[name]||'Control Center';
  if(name==='people') loadPeople(); if(name==='audit') loadAudit();
}

async function boot(user){
  state.authUser=user;
  if(!user){
    stopPersonWatch();
    state.person=null;
    showOnly('login');
    try{
      const reason=sessionStorage.getItem(REVOCATION_REASON_KEY);
      if(reason){setStatus(reason);sessionStorage.removeItem(REVOCATION_REASON_KEY);}
    }catch{}
    return;
  }
  try{
    const person=await currentPerson(user); state.person=person;
    if(!person||person.active!==true){ setBlocked(`A conta ${user.email||''} ainda não foi autorizada no LPS Control Center.`); return; }
    adminUI(); renderUser(); await loadProjects(); showOnly('app'); startPersonWatch(user); await audit('login','Acesso autenticado ao Control Center');
  }catch(err){
    console.error('Falha ao validar permissões:',err);
    setBlocked(`Não foi possível validar suas permissões. ${err?.code ? `Código: ${err.code}. ` : ''}Verifique se o Firestore foi criado e se as regras foram publicadas.`);
  }
}

function wireUI(){
  $('emailForm')?.addEventListener('submit',async e=>{ e.preventDefault(); try{ setStatus('Validando...'); await signInWithEmailAndPassword(state.auth,normalizeEmail($('email').value),$('password').value); }catch(err){ setStatus(err?.message||'Falha no login.'); } });
  $('resetPassword')?.addEventListener('click',async()=>{ const email=normalizeEmail($('email').value); if(!email){setStatus('Informe o e-mail primeiro.');return;} try{await sendPasswordResetEmail(state.auth,email);setStatus('E-mail de redefinição enviado.');}catch(err){setStatus(err?.message||'Falha ao enviar.');} });
  $('logout')?.addEventListener('click',()=>signOut(state.auth));
  $('blockedLogout')?.addEventListener('click',()=>signOut(state.auth));
  $('newProject')?.addEventListener('click',()=>openProject()); $('projectForm')?.addEventListener('submit',e=>saveProject(e).catch(err=>alert(err?.message||err))); $('cancelProject')?.addEventListener('click',()=> $('projectDialog').close());
  $('newPerson')?.addEventListener('click',()=>openPerson()); $('personForm')?.addEventListener('submit',e=>savePerson(e).catch(err=>alert(err?.message||err))); $('cancelPerson')?.addEventListener('click',()=> $('personDialog').close());
  $('importSeed')?.addEventListener('click',async()=>{ try{await importSeed();}catch(err){alert(err?.message||err);} });
  document.querySelectorAll('.nav').forEach(btn=>btn.addEventListener('click',()=>switchView(btn.dataset.view)));
}

async function start(){
  try{
    const firebaseApp=initializeApp(firebaseConfig);
    await initAppCheck(firebaseApp);
    state.auth=getAuth(firebaseApp);
    state.db=getFirestore(firebaseApp);
    wireUI();
    try{ await setPersistence(state.auth,browserLocalPersistence); }
    catch(err){ console.warn('Persistência local indisponível; sessão continuará sem persistência explícita:',err?.code||err?.message||err); }
    onAuthStateChanged(state.auth, user=>boot(user), err=>{
      console.error('Auth state error:',err);
      setBlocked(`Falha ao iniciar autenticação${err?.code?` (${err.code})`:''}.`);
    });
  }catch(err){
    console.error('Falha de inicialização do LPS Control Center:',err);
    const message = err?.message || String(err);
    setBlocked(`Falha ao iniciar o Control Center. ${message}`);
  }
}

window.__LPS_CONTROL_CENTER_BOOTED__=true;
start();