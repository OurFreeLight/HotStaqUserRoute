# HotStaq User Route
Documentation is coming...

This supports MariaDB and PostgreSQL databases. MySQL support is experimental and most likely does not work!

For API documentation, please see the [OpenAPI Documentation](./api.md)

## Getting Started
Simply install this package into your HotStaq project by doing:
```console
npm install @hotstaq/userroute
```

Then in your code base, navigate to your API that extends the HotAPI class and add the new route:
```javascript
this.addRoute (new UserRoute (this));
```

Now your API will have the user route available with all the endpoints listed in the OpenAPI documentation.

**NOTE** The environment variable `JWT_SECRET_KEY` is required for this package to work. This is the secret key used to sign the JWT tokens.

## Environment Variables
* JWT_SECRET_KEY
    * Description: The JWT secret key to use for signing tokens.
    * Type: string
    * Default: 
* AUTO_VERIFY_USERS
    * Description: If set to 1, users will be automatically verified upon registration. This is mostly for development purposes.
    * Type: number
    * Default: 0
* DISABLE_REHASHING
    * Description: If set to 1, passwords will not be rehashed after a successful login.
    * Type: number
    * Default: 0
* DATABASE_DISABLE
    * Description: If set to 1, a database connection will not be established.
    * Type: number
    * Default: 0

## API Generation
To generate a web client for use on a website enter:
```console
npm run build-web
```

To generate the OpenAPI 3.0.0 YAML documentation enter:
```console
npm run build-doc
```