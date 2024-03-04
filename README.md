# Http-Server

Fast, minimalist HTTP/1.1 server for NodeJS.

```js
    const httpServer = require("/path/to/http-server");
    const server = new httpServer.httpServer();

    server.get('/', function (req, res) {
        res.send('Hello World!');
    })

    server.get('/app/*', function (req, res) {
        res.send('Hello Wildcard!');
    })

    server.listen(3000, "127.0.0.1", function() {
        console.log("Server listening on 127.0.0.1:3000");
    })
```

# NOTE

This module shouldn't be used in real world applications.
I've made it only to enhance my HTTP knowledge, and to fully understand how HTTP/1.1 works under the hood, using only the net module for TCP requests.
For real-world use, please use [expressjs](https://github.com/expressjs/express) or other similar modules.

# Features

* Robust routing
* High performance
* Automatic cookie handling
* Automatic header handling
* Wildcards
* Middleware support

# Quickstart

```bash
git clone https://github.com/JijaProGamer/http-server # copy the repository
cd http-server
node example/test.js
```

Will open a server on 127.0.0.1:8500, with a simple form.

# Documentation

All the documentation can be found in the [Page Wiki](https://pages.github.com/).