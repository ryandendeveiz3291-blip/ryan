# FRONTIER

Jogo de aventura em primeira pessoa. [Jogar agora](https://ryandendeveiz3291-blip.github.io/ryan/).

Para abrir localmente, abra [jogo.html](./jogo.html) em um navegador.

## Rank Dono

O menu de ranks abre com `L`. O rank Dono usa um Cloudflare Worker; a senha não deve ser colocada no HTML, no Git ou em mensagens.

1. Use Wrangler v4.36.0 ou mais recente e autentique: `npx wrangler@latest login`.
2. Publique o Worker: `npx wrangler@latest deploy`.
3. No painel Cloudflare, abra o Worker `frontier-owner-auth` → **Settings** → **Variables and Secrets** e adicione `OWNER_PASSWORD` e `SESSION_SECRET` como **Secrets**. Use uma senha nova e aleatória com pelo menos 24 caracteres e uma chave de sessão aleatória com pelo menos 32 caracteres; não reutilize senha compartilhada em conversa.
4. Copie a URL pública `workers.dev` exibida pelo deploy e substitua o valor completo de `OWNER_AUTH_API` no [jogo.html](./jogo.html) pela URL base do Worker (sem `/api`). Se o deploy reclamar que o ID do rate limiter já existe na conta, escolha um ID numérico único em `wrangler.toml` e tente novamente.
5. Publique a atualização do jogo no GitHub Pages.

O Worker permite até cinco tentativas de login por minuto e emite sessões assinadas com validade de oito horas. O limite do Cloudflare é aproximado por localização. O rank Dono é local e cosmético; a presença multiplayer existente não autentica permissões de Dono. A requisição de login pode ser inspecionada no DevTools do navegador usado para entrar, embora a senha não esteja no código público.

Para validar a autenticação localmente: `node --test worker/index.test.mjs`.
