# LPS Control Center

Central de autenticação, projetos e permissões da Lean Performance Solutions.

## Objetivo

- Login único para os projetos LPS.
- Cadastro de pessoas e empresas.
- Permissões por projeto/obra.
- Perfis: Visualizador, Operador, Planejamento, Administrador de Obra e Admin LPS.
- Catálogo dos projetos GitHub e links publicados.
- Base para proteger os Painéis de Bordo sem alterar seus dados.

## Firebase

Projeto: `lps-control-center`

Ativar no Firebase Console:

1. Authentication: Google e Email/Senha.
2. Firestore Database em modo Production.
3. Publicar `firestore.rules`.
4. Criar manualmente o primeiro documento em `people/<email-normalizado>` com `active: true` e `globalRole: "super_admin"`.

## Segurança

A configuração Web do Firebase é pública por natureza. A autorização real é feita por Firebase Authentication + Firestore Security Rules. O frontend nunca deve ser tratado como fronteira de segurança.

## Integração futura

Cada Painel de Bordo continuará com seu próprio link. Ao abrir, verificará a sessão no LPS Control Center e a permissão para aquela obra antes de liberar o painel.
