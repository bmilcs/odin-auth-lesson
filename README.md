# Odin Project Auth Lesson Tutorial

Technology:

- Express
- MongoDB
- `passport`: authentication middleware
  - Local Strategy: user/password, validates credentials vs. database entries
  - Serialization: `serializeUser` & `deserializeUser`
    - Store & retrieve user info in the session
- `bcryptjs`: hashing passwords
  - Encrypt, decrypt/compare passwords
  - Salt: additional random characters added to a password before it's fed into bcrypt
- Cookies
  - Store authentication/session info/tokens on the client by the server
  - Added to all http requests sent to the server

[Source](https://www.theodinproject.com/lessons/nodejs-authentication-basics)
