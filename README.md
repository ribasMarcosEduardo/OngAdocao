# ONG Adoção — Aplicação Cliente (Relying Party OIDC)

Trabalho **A1/3 — 33506 Cyber Security (UNOESC)**: *Autenticação e Autorização — OAuth 2.0 + OpenID Connect (Authorization Code com PKCE)*.

Sistema web de uma ONG de adoção de animais (Spring Boot + Thymeleaf, **renderizado no servidor**; nenhum JavaScript/Node no back-end). Neste trabalho ele é o **Cliente / Relying Party**: **não tem tela de senha, não recebe, transmite nem armazena senha**. A autenticação é delegada ao Servidor de Autorização (`auth-server`, Opção 1) pelo fluxo **Authorization Code + PKCE (S256)**; a aplicação **valida o ID Token (JWT RS256)** antes de criar a sessão local.

---

## 1. Tecnologias
Java **17** · Spring Boot **3.5.3** (Web, Security, Data JPA, Thymeleaf, Validation) · MySQL · Nimbus JOSE+JWT **9.47** · Lombok · Maven.

## 2. Estrutura (parte de segurança/OIDC)

```
src/main/java/bdTrabalho/OngAplication
├── OngAplicationApplication.java        main + @ConfigurationPropertiesScan
├── config/HttpClientConfig.java         RestTemplates com timeout (+ truststore p/ o provedor)
├── security/
│   ├── OidcProperties.java              configuração "oidc.*" (record)
│   ├── OidcAuthController.java          /login, /oauth2/login, /callback  ← o fluxo OIDC
│   ├── IdTokenValidatorService.java     validação do ID Token (checklist 4.3)
│   ├── SecurityConfig.java              regras de acesso, logout
│   ├── SessionRevalidationFilter.java   expiração absoluta + role relida a cada requisição
│   ├── RoleUtil.java                    role do claim → ROLE_*
│   └── DataSeederConfig.java            pré-vincula (iss+sub) os usuários de teste
├── controller/AdminController.java      GET /admin (somente ROLE_ADMIN)
├── controller/…                         animais, adoções, campanhas, prontuários, usuários etc.
├── model/Usuarios.java                  tabela Usuarios (id, user_name, full_name, oidc_sub, oidc_issuer, role, created_at…)
└── service|repository|validator|dto/…   regras de negócio da ONG
src/test/java/…/security/IdTokenValidatorServiceTest.java    testes negativos #1–#7 e #12
scripts/gen-certs.sh|.cmd · scripts/negative_http_tests.py · docs/ (Postman, esqueleto do relatório)
```

---

## 3. Como subir

### 3.1 Pré-requisitos
JDK 17+ (com `keytool`) · Maven (ou `mvnw`) · **MySQL** rodando · o **auth-server já no ar** (https://localhost:9000) e o arquivo `auth-server/certs/auth-server.crt` gerado por ele.

### 3.2 Passo a passo
1. **Banco:** crie o schema (as tabelas o Hibernate cria — `ddl-auto: update`):
   ```sql
   CREATE DATABASE ong_adocao CHARACTER SET utf8mb4;
   CREATE USER 'ong_app'@'localhost' IDENTIFIED BY '<senha>';
   GRANT ALL ON ong_adocao.* TO 'ong_app'@'localhost';
   ```
   Se você vem de uma versão anterior: `ALTER TABLE Usuarios DROP COLUMN senha;` (a coluna de senha não existe mais).
2. **Variáveis:** `cp .env.example .env` e preencha (o `.env` é ignorado pelo git; lido via `spring.config.import`).

   | Variável | Obrigatória | Descrição |
   |---|---|---|
   | `MYSQL_PASSWORD` | sim | senha do banco (sem valor padrão) |
   | `MYSQL_HOST` / `MYSQL_PORT` / `MYSQL_USER` | não | padrão `localhost` / `3306` / `root` |
   | `OIDC_CLIENT_ID` | sim | igual ao do auth-server (`ong-adocao-client`) |
   | `OIDC_CLIENT_SECRET` | sim | **o mesmo** segredo do auth-server |
   | `OIDC_ISSUER` | não | `https://localhost:9000` |
   | `OIDC_REDIRECT_URI` | não | `https://localhost:8443/callback` (idêntica à registrada no provedor) |
   | `OIDC_POST_LOGOUT_REDIRECT_URI` | não | `https://localhost:8443/login?logout=true` |
   | `OIDC_AUTO_PROVISION` | não | `true`: quem se cadastrou no provedor entra e vira usuário local; `false` (padrão): só entram `sub` já vinculados |
   | `APP_KEYSTORE_PASSWORD` | sim | senha do keystore TLS da aplicação |
   | `OIDC_TRUSTSTORE_PASSWORD` | sim | senha do truststore que confia no provedor |

3. **Certificados** (TLS da aplicação + truststore com o certificado do auth-server):
   ```bash
   APP_KEYSTORE_PASSWORD=... OIDC_TRUSTSTORE_PASSWORD=... \
     ./scripts/gen-certs.sh ../auth-server/certs/auth-server.crt
   # Windows: scripts\gen-certs.cmd ..\auth-server\certs\auth-server.crt
   ```
   Gera `certs/app.p12` e `certs/truststore.p12`.
4. **Executar:** `./mvnw spring-boot:run`
5. **Usar:** abra **https://localhost:8443** (aceite o certificado autoassinado) → **Entrar**.
   - Já tem conta? Entre com seu usuário/senha **na tela do provedor**.
   - Não tem? Clique em *Criar conta* na tela do provedor (`https://localhost:9000/register`), volte e clique em **Entrar**.
   - Contas de teste do provedor: `admin` e `operador` (senhas do `.env` do auth-server).

---

## 4. O fluxo, método a método (`OidcAuthController`)

| Passo do enunciado (4.2) | Onde acontece |
|---|---|
| 1. gerar `state`, `nonce`, `code_verifier`, `code_challenge` e guardar na sessão | `startOidcLogin()` → `generateRandomUrlSafe()` (SecureRandom, 256 bits) e `computeS256Challenge()` |
| 2. redirecionar ao `authorization_endpoint` | `startOidcLogin()` (`response_type=code`, `scope=openid profile email`, `code_challenge_method=S256`) |
| 3. usuário digita a senha **no provedor** | — a aplicação não participa |
| 4–5. callback e **conferência do `state`** (aborta se divergir/ausente, antes do `/token`) | `handleCallback()` + `constantTimeEquals()`; `limparEstadoOidc()` faz o state/nonce/verifier valerem **uma só vez** |
| 6. POST no `/token` (code, redirect_uri, code_verifier, credenciais) — **uma única tentativa**, com timeout | `handleCallback()` com o bean `oidcRestTemplate` (conexão 3 s / leitura 5 s) |
| 7–9. decompor (log), validar o ID Token, extrair o `sub` | `IdTokenValidatorService.validateAndParse()` |
| (checklist 10) `sub` do `/userinfo` == `sub` do ID Token | `handleCallback()` — o `sub` é obrigatório na resposta |
| 10. localizar o usuário por `sub` (e `iss`); criar ou recusar | `UsuarioRepository.findByOidcSub`, `provisionar()`; recusa se `OIDC_AUTO_PROVISION=false` |
| 12. role vinda do claim `role` (lista fixa), sincronizada na tabela local | `RoleUtil.fromVerifiedClaim()` em `handleCallback()` |
| 11. nova sessão local, **id rotacionado**, só o id do usuário nela | `request.changeSessionId()` + `RoleUtil.SESS_USER_ID` / `SESS_CREATED_AT` |
| 4.6 erro do provedor / falhas | mensagem **genérica** na tela (`erro-auth.html`); detalhe só no log |

### 4.1 Validação do ID Token — `IdTokenValidatorService.validateAndParse(token, nonce)`
Ordem das verificações (cada uma é um item do checklist 4.3):

1. formato JWS com 3 partes; Base64URL válido; **log das 3 partes decodificadas** (evidência do relatório);
2. **algoritmo**: lê o `alg` do header *bruto* e exige estar em `ALLOWED_ALGS = {RS256}` → `none`, HS256 etc. são recusados **antes** de qualquer outra coisa; o verificador é **sempre** RSA (o `alg` do token nunca escolhe o método);
3. `kid` obrigatório; chave buscada no **JWKS** (`jwks_uri` vem da **descoberta**, `resolveJwksUri()`, que também confere `issuer` publicado == configurado); chave inexistente = erro; `use=sig`/`alg` da chave conferidos;
4. **assinatura** (`RSASSAVerifier`);
5. `iss` == issuer; `aud` contém o `client_id` (e `azp` se houver mais de um); `exp` no futuro (tolerância 120 s); `iat` não no futuro; `nonce` idêntico ao enviado; `sub` presente.

### 4.2 Sessão e autorização
- Cookie `ONG_SESSION_ID`: `HttpOnly; Secure; SameSite=Lax; Path=/`; inatividade **30 min** (`server.servlet.session.timeout`); **absoluta 8 h** (`SessionRevalidationFilter`).
- `SessionRevalidationFilter.doFilterInternal()` roda **antes da autorização**, a cada requisição: confere a expiração absoluta e **relê o usuário no banco**, reconstruindo a autoridade com a role atual (usuário removido/expirado → sessão invalidada → `/login?expired=true`).
- A role é decidida **depois** da validação criptográfica do token e aplicada **no servidor** (`SecurityConfig` + `@PreAuthorize` em `AdminController.admin()`), nunca só escondendo botões.
- **Logout** (`POST /logout`, com CSRF): invalida a sessão local e redireciona ao `/logout` do provedor, que encerra a sessão lá e devolve o navegador a `/login?logout=true`. Nenhum token é guardado em sessão ou banco.

### 4.3 Rotas e permissões (`SecurityConfig.securityFilterChain`)

| Rota | Quem acessa |
|---|---|
| `/login`, `/oauth2/**`, `/callback`, `/acesso-negado`, `/erro-auth`, estáticos | público |
| `/admin`, `/admin/**` | **somente ADMIN** (outros: **HTTP 403**) |
| `DELETE /**`, `/*/excluir`, `/usuario/editar` | somente ADMIN |
| `/animal/**`, `/campanha/**`, `/prontuario/**`, `/vacina/**`, `/doenca/**`, `/contato/**`, `/endereco/**`, `/usuario/listaUsuario`, `/adocao/listar|aprovar|reprovar` | ADMIN e USER (operador) |
| demais (ex.: `/adocao`, `/adocao/minhas-solicitacoes`) | qualquer usuário autenticado (ex.: `adotante`) |

Roles: `admin` (acesso total) · `user` (operador: gestão) · `adotante` (solicita adoções). Vêm do **claim `role`** do token; ausente/inválido ⇒ `adotante` (menor privilégio).

---

## 5. Referência rápida de classes

| Classe | Métodos principais |
|---|---|
| `OidcAuthController` | `loginPage`, `startOidcLogin`, `handleCallback`, `provisionar`, `erro`, `limparEstadoOidc`, `constantTimeEquals`, `generateRandomUrlSafe`, `computeS256Challenge`, `erroAuthPage`, `acessoNegadoPage` |
| `IdTokenValidatorService` | `validateAndParse`, `resolveJwksUri` |
| `SecurityConfig` | `securityContextRepository`, `securityFilterChain` (sem `formLogin`, sem `UserDetailsService`) |
| `SessionRevalidationFilter` | `doFilterInternal` |
| `RoleUtil` | `fromVerifiedClaim`, `toSpringRole`, constantes `SESS_USER_ID`, `SESS_CREATED_AT` |
| `HttpClientConfig` | `restTemplate` (geral/ViaCEP), `oidcRestTemplate` (timeouts + truststore `oidc`) |
| `DataSeederConfig` | `seedOidcUsers`, `seed` |
| `AdminController` | `admin` (`GET /admin`) |

## 6. Tabela `Usuarios` (4.1 do enunciado)
`id` (PK int) · `user_name` (único, **só exibição**) · `full_name` · `oidc_sub` (único — chave de vínculo) · `oidc_issuer` (o vínculo é **iss + sub**) · `role` · `created_at` · e os dados da ONG (`nome`, `cpf`, `data_nascimento`, `genero`, `foto`…). **Não existe coluna de senha.** E-mail/nome nunca são identificador.

**Primeiro login:** se o `sub` não existe e `OIDC_AUTO_PROVISION=true`, `provisionar()` cria o registro **somente com dados do token já validado**; `user_name` = `preferred_username` do provedor (ou e-mail só se `email_verified=true`, ou um nome derivado do `sub`). Com `false`, o login é recusado (*"Seu usuário não está autorizado nesta aplicação."*).

---

## 7. Testes

| Teste do item 5 | Como executar |
|---|---|
| **#1–#7, #12** (ID Token forjado: alg none, HS256 com chave pública, aud, iss, exp, iat, nonce, assinatura adulterada) | `./mvnw test -Dtest=IdTokenValidatorServiceTest` → saída em `target/surefire-reports/` |
| **#8–#11, #13–#15** | **Postman** (`docs/ONG-OIDC.postman_collection.json`, pastas 2 a 7) **ou** `python scripts/negative_http_tests.py` |

Postman: importe a coleção e o environment, preencha `client_secret`, `op_pass`, `admin_pass`; desligue a verificação de certificado (ou importe `auth-server.crt` em *Settings → Certificates*) e rode as pastas em ordem no Collection Runner. A pasta **7** cobre: `/login` sem campo de senha, `/oauth2/login` (parâmetros PKCE), **#8** (state divergente/ausente), erro do provedor, `/admin` sem login e **#13** (`/admin` com `role=user` → 403; com `admin` → 200).

Script Python: `pip install requests` e defina `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OPERADOR_PASSWORD`, `ADMIN_PASSWORD` (opcional `CA_CERT=../auth-server/certs/auth-server.crt`); imprime a tabela PASS/FAIL.

## 8. Problemas comuns

| Sintoma | Causa / solução |
|---|---|
| `PKIX path building failed` ao logar | o truststore não tem o certificado do auth-server → refaça `gen-certs` apontando para o `.crt` atual |
| Tela *"Não foi possível concluir o login"* | veja o **log** da aplicação: o motivo real (issuer, nonce, assinatura…) só aparece lá |
| *"Seu usuário não está autorizado"* | `OIDC_AUTO_PROVISION=false` e o `sub` não está vinculado → use `true` ou cadastre o `sub` |
| Volta ao login em loop | acessando por `http://`; use sempre `https://localhost:8443` (cookie `Secure`) |
| `Could not resolve placeholder` | falta variável no `.env` (rode a partir da pasta do projeto) |
| `Access denied for user` (MySQL) | `MYSQL_USER`/`MYSQL_PASSWORD` incorretos |
| 403 depois de ficar parado | sessão expirou (30 min inatividade / 8 h absoluta) → faça login de novo |

## 9. Observações
- A role é gerida **no provedor**; mudar a role na tela de usuários da aplicação vale só até o próximo login.
- Os testes `contextLoads` antigos (`@SpringBootTest`) precisam do banco e das variáveis; rode os testes de segurança com `-Dtest=IdTokenValidatorServiceTest`.
