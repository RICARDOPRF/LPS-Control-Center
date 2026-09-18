import { initializeApp, getApps, getApp } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js';
import {
  getAuth,
  onAuthStateChanged,
  setPersistence,
  browserLocalPersistence
} from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js';
import {
  getFirestore,
  doc,
  getDoc,
  onSnapshot
} from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js';
import { firebaseConfig } from './firebase-config.js';

const CONTROL_CENTER_URL = 'https://ricardoprf.github.io/LPS-Control-Center/';
const GUARD_STYLE_ID = 'lps-central-guard-style';

const normalizeEmail = value => String(value || '').trim().toLowerCase();

function ensureGuardStyle() {
  if (document.getElementById(GUARD_STYLE_ID)) return;
  const style = document.createElement('style');
  style.id = GUARD_STYLE_ID;
  style.textContent = `
    html.lps-guard-validating body { visibility: hidden !important; }
    .lps-guard-screen {
      position: fixed; inset: 0; z-index: 2147483647;
      display: grid; place-items: center; padding: 24px;
      background: radial-gradient(circle at top, #1c2f27 0%, #08100d 52%, #050807 100%);
      color: #f5f3e9; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    .lps-guard-card {
      width: min(560px, 100%); border: 1px solid rgba(213,178,92,.28);
      border-radius: 22px; padding: 30px; background: rgba(10,18,15,.92);
      box-shadow: 0 28px 90px rgba(0,0,0,.45); text-align: center;
    }
    .lps-guard-brand { font-size: 12px; letter-spacing: .22em; color: #d5b25c; font-weight: 800; }
    .lps-guard-card h1 { margin: 12px 0 10px; font-size: clamp(24px, 4vw, 36px); }
    .lps-guard-card p { margin: 0 auto 20px; max-width: 46ch; color: #b9c2bd; line-height: 1.55; }
    .lps-guard-card a { display:inline-flex; align-items:center; justify-content:center; min-height:44px; padding:0 18px; border-radius:12px; text-decoration:none; background:#d5b25c; color:#11150f; font-weight:800; }
  `;
  document.head.appendChild(style);
}

function beginValidation() {
  ensureGuardStyle();
  document.documentElement.classList.add('lps-guard-validating');
}

function endValidation() {
  document.documentElement.classList.remove('lps-guard-validating');
}

function buildControlCenterUrl(projectId, permission = 'view') {
  const url = new URL(CONTROL_CENTER_URL);
  url.searchParams.set('returnTo', window.location.href);
  if (projectId) url.searchParams.set('project', projectId);
  if (permission) url.searchParams.set('permission', permission);
  return url.toString();
}

function renderDenied({ title, message, projectId, permission }) {
  endValidation();
  document.querySelector('.lps-guard-screen')?.remove();

  const screen = document.createElement('div');
  screen.className = 'lps-guard-screen';

  const card = document.createElement('section');
  card.className = 'lps-guard-card';
  card.setAttribute('role', 'alert');
  card.setAttribute('aria-live', 'assertive');

  const brand = document.createElement('div');
  brand.className = 'lps-guard-brand';
  brand.textContent = 'LEAN PERFORMANCE SOLUTIONS';

  const heading = document.createElement('h1');
  heading.textContent = String(title || 'Acesso bloqueado');

  const paragraph = document.createElement('p');
  paragraph.textContent = String(message || 'Seu acesso não pôde ser validado.');

  const link = document.createElement('a');
  link.href = buildControlCenterUrl(projectId, permission);
  link.textContent = 'Abrir LPS Control Center';

  card.append(brand, heading, paragraph, link);
  screen.appendChild(card);
  document.body.appendChild(screen);
}

function authUserOnce(auth) {
  return new Promise((resolve, reject) => {
    let unsubscribe = () => {};
    unsubscribe = onAuthStateChanged(auth, user => {
      unsubscribe();
      resolve(user);
    }, error => {
      unsubscribe();
      reject(error);
    });
  });
}

function permissionGranted(person, projectId, permission) {
  if (person?.active !== true) return false;
  if (person?.globalRole === 'super_admin') return true;
  return person?.projects?.[projectId]?.[permission] === true;
}

function startLiveAccessWatch(db, { email, user, projectId, permission }) {
  let revoked = false;
  let personState = null;
  let projectState = null;

  const revoke = (reason, title, message) => {
    if (revoked) return;
    revoked = true;
    renderDenied({ title, message, projectId, permission });
    window.dispatchEvent(new CustomEvent('lps:access-revoked', {
      detail: { reason, user, person: personState, project: projectState, projectId, permission }
    }));
  };

  const stopPerson = onSnapshot(doc(db, 'people', email), snap => {
    personState = snap.exists() ? { id: snap.id, ...snap.data() } : null;
    if (!permissionGranted(personState, projectId, permission)) {
      revoke(
        'permission_revoked',
        'Acesso revogado',
        'Sua conta foi bloqueada ou sua permissão para este projeto foi removida. O acesso a esta tela foi encerrado.'
      );
    }
  }, error => {
    console.warn('LPS Guard: monitor de pessoa indisponível.', error?.code || error?.message || error);
    revoke(
      'person_watch_failed',
      'Acesso não pôde ser revalidado',
      'A validação contínua da sua conta falhou. Por segurança, esta tela foi bloqueada.'
    );
  });

  const stopProject = onSnapshot(doc(db, 'projects', projectId), snap => {
    projectState = snap.exists() ? { id: snap.id, ...snap.data() } : null;
    if (!projectState || projectState.active === false) {
      revoke(
        'project_inactive',
        'Projeto indisponível',
        'Este projeto foi desativado no LPS Control Center. O acesso a esta tela foi encerrado.'
      );
    }
  }, error => {
    console.warn('LPS Guard: monitor de projeto indisponível.', error?.code || error?.message || error);
    revoke(
      'project_watch_failed',
      'Projeto não pôde ser revalidado',
      'A validação contínua do projeto falhou. Por segurança, esta tela foi bloqueada.'
    );
  });

  const stop = () => {
    try { stopPerson(); } catch {}
    try { stopProject(); } catch {}
  };
  window.addEventListener('pagehide', stop, { once: true });
  return stop;
}

export async function requireProjectAccess(projectId, options = {}) {
  if (!projectId) throw new Error('LPS Guard: projectId é obrigatório.');

  const permission = options.permission || 'view';
  const redirectUnauthenticated = options.redirectUnauthenticated !== false;
  const liveRevocation = options.liveRevocation !== false;
  const app = getApps().length ? getApp() : initializeApp(firebaseConfig);
  const auth = getAuth(app);
  const db = getFirestore(app);

  beginValidation();

  try {
    try { await setPersistence(auth, browserLocalPersistence); }
    catch (error) { console.warn('LPS Guard: persistência local indisponível.', error?.code || error?.message || error); }

    const user = await authUserOnce(auth);
    if (!user?.email) {
      if (redirectUnauthenticated) {
        window.location.replace(buildControlCenterUrl(projectId, permission));
        return new Promise(() => {});
      }
      renderDenied({
        title: 'Autenticação necessária',
        message: 'Entre pelo LPS Control Center para acessar este sistema.',
        projectId,
        permission
      });
      return { allowed: false, reason: 'unauthenticated', user: null, person: null, project: null };
    }

    const email = normalizeEmail(user.email);
    const personSnap = await getDoc(doc(db, 'people', email));
    const person = personSnap.exists() ? { id: personSnap.id, ...personSnap.data() } : null;

    if (!permissionGranted(person, projectId, permission)) {
      renderDenied({
        title: 'Acesso não liberado',
        message: `Sua conta não possui a permissão “${permission}” para este projeto. Solicite a liberação no LPS Control Center.`,
        projectId,
        permission
      });
      return { allowed: false, reason: 'forbidden', user, person, project: null };
    }

    const projectSnap = await getDoc(doc(db, 'projects', projectId));
    const project = projectSnap.exists() ? { id: projectSnap.id, ...projectSnap.data() } : null;

    if (!project || project.active === false) {
      renderDenied({
        title: 'Projeto indisponível',
        message: 'Este projeto não está ativo no LPS Control Center.',
        projectId,
        permission
      });
      return { allowed: false, reason: 'project_inactive', user, person, project };
    }

    const stopWatching = liveRevocation
      ? startLiveAccessWatch(db, { email, user, projectId, permission })
      : () => {};

    endValidation();
    window.dispatchEvent(new CustomEvent('lps:access-granted', {
      detail: { user, person, project, projectId, permission, liveRevocation }
    }));
    return { allowed: true, user, person, project, stopWatching };
  } catch (error) {
    console.error('LPS Guard:', error);
    renderDenied({
      title: 'Falha na validação',
      message: 'Não foi possível validar seu acesso com segurança. Tente novamente pelo LPS Control Center.',
      projectId,
      permission
    });
    return { allowed: false, reason: 'validation_error', error, user: null, person: null, project: null };
  }
}

export { CONTROL_CENTER_URL };
