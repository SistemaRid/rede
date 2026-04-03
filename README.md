# Noite

Chat privado em tela escura, com senha por aparelho e mensagens que expiram em 24 horas.

## O que configurar

1. Abra `app.js` e preencha `firebaseConfig`.
2. No Firebase Console, ative:
   - `Authentication > Sign-in method > Anonymous`
   - `Firestore Database`
3. Publique as regras de `firestore.rules`.
4. Opcional, mas recomendado:
   - Ative TTL no Firestore para o campo `expiresAt` da subcolecao `messages`.

## Estrutura usada

- `profiles/{uid}`: nome publico pesquisavel
- `secrets/{uid}`: hash da senha do aparelho
- `conversations/{conversationId}`
- `conversations/{conversationId}/messages/{messageId}`

## Observacao importante

No navegador, nao existe como impedir screenshot do sistema operacional com garantia total.
Este app aplica protecao visual para:

- `Ctrl/Cmd + P` e impressao
- eventos de `PrintScreen` quando o navegador detectar
- perda de foco/visibilidade

Isso ajuda, mas nao substitui seguranca real de sistema operacional ou app nativo.
