# NETAuthorityAuthorization
.NET Authentication and Authorization


## ASP.NET Core Identity
- Fresh and modern look at the membership system
- Implemented as Razor class library in ASP.NET Core
- ASP.NET Core Identity is a user store and much more
- Requires Minimal knowledge of identity and security.
- Includes extensive helper methods that performs the essential core functionality in identity management development.
- Some of the helper functionality includes methods for password hashing, Password validation, Password reset,Confirmation,User lockout,Multi-factor authentication,Token generation,External identity providers and much more.
- Net core identity has many helper methods around authentication, but do not confuse it as an authentication library. Authentication within your application is still handled by your authentication middleware like cookies
or OpenID connect middleware.
- .Net identity may be used to verify the credentials, but this middleware libraries are responsible for authenticating each request in your application.
- Also, make a note and always remember that the.Net Core Identity Library and Identity Server are two different concepts and libraries.
- Identity server has been renamed to Duende Server that offers protocol support for OpenID connect, whereas the.Net core identity is your user store.
- Identity Server is an authentication server that implements OAuth 2.0 and Open ID Connect(OIDC)
- Great question! Here's a concise comparison between ASP.NETCore Identity and IdentityServer:

## ASP.NETCore Identity
- Purpose: Manages user authentication and authorization within your application.
- Features: Handles user registration, login, password management, roles, and claims.
- Use Case: Ideal for applications that need to manage user accounts and authentication internally2.
- Integration: Easily integrates with ASP.NETCore applications.

## IdentityServer
- Purpose: Provides an implementation of OpenID Connect and OAuth 2.0 protocols for authentication and authorization.
- Features: Supports Single Sign-On (SSO), token-based authentication, and API protection.
- Use Case: Suitable for applications that need to support multiple clients (e.g., web, mobile apps) and external identity providers.
- Integration: Can be used with ASP.NETCore Identity for user management, but also supports other identity providers.

## Key Differences
- Scope: ASP.NETCore Identity is focused on managing user accounts within your application, while IdentityServer is focused on providing authentication and authorization services for multiple clients and external identity providers3.
- Protocols: IdentityServer supports OpenID Connect and OAuth 2.0, which are standards for authentication and authorization, whereas ASP.NETCore Identity does not inherently support these protocols3.
- Flexibility: IdentityServer offers more flexibility for integrating with various external identity providers and supporting different types of clients (web, mobile, etc.), whereas ASP.NETCore Identity is more tightly integrated with ASP.NETCore applications.

## Authentication and Authorization
- Who you are is authentication and what access do you have is authorization

## Types of authentication
- Cookie based authentication: Default method for very long
- This authentication is stateful
- Server needs to keep track of active sessions in the database and on the front-end a cookie is created that holds a session identifier and hence the name cookie based authentication
- We also have token based authentication
- More recent
- Used with SPA and IOT
- Done using JWT
- Here server doesnot keep track of which users are logged in, each request to the server is accompanied with a token which the server can then use to identify the user
- Token based authentication is stateless
- Cookie based authentication is used when we have username and password in our website
- Token based authentication may use external login for authentication like using Google or Facebook for login
- We are redirected to Facebook website where we login and then we are redirected to web app with a token

- ## Cookie based vs Token based
- ### Flow of Cookie based authentication
- In Cookie based, initially the user enters their username and password
- Server verifies the credentials are correct and then it creates a session which is stored in the database and then inside a cookie
- A cookie with the session Id is placed in the user's browser with a certain expiration time
- On subsequent requests, session Id is verified against a database
- If user logouts of the app, the session is destroyed both client-side and server-side
- ### Flow of Token based authentication
- User enters their login credentials
- Server verifies if credentials are valid and it returns a signed token
- This token is stored client side either in local storage or in a HTTP Only Cookie
- Subsequent requests to the server will include this token
- When server receives the token, it will decode the JWT and if the token is valid
- Once the user logouts, the token is destroyed in the client side.
- Token based authentication is more common in mobile apps and SPAs
- Cookie based is more common in server to server communication

## ASP.NET Identity Structure and Architecture
- Main goal is user store and user management
- User store and Role Store (DAL): They abstract away the underlying database
- This store allows us to change database providers
- Next layer is the managers like User Manager & Role Manager: Here all business logic lives: hashing password, managing users
- They are like the gateway in .Net Core Identity Library
- ![alt text](image.png)
- Final Layer is library of methods that support out of the box integration with external library
- Example is Sign In Manager
- Underlying all of this is a common set of entities like user, role and user-role
- We will use EFCore IdentityDbContext to use these entities.

## 2 types of authorization
- Role based authorization like customer, manager, admin, front desk etc
- Based on role, we determine what access they have
- Claims based authorization: This is a piece of information about a user
- It can be gender, email
- Customer with more than 20 bookings as elite customer
- We can use that claim to give that customer some special privileges
- Claims are like key-value pairs
- Roles are just keys
- We can use a combination of claims and roles to grant access