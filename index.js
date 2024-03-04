const net = require("net")
const fs = require("fs")
const stream = require("stream")
const wcmatch = require('wildcard-match')

function parseString(value) {
    const dateValue = new Date(value);
    if (!isNaN(dateValue.getTime()) && /^\d{4}-\d{2}-\d{2}/.test(value)) {
      return dateValue;
    }
  
    try {
      const jsonValue = JSON.parse(value);
      return jsonValue;
    } catch (error) {
    }
  
    const numberValue = Number(value);
    if (!isNaN(numberValue)) {
      return numberValue;
    }
  
    return value;
  }

function splitBuffer(buffer, delimiter) {
    const delimiterBuffer = Buffer.from(delimiter);
    const result = [];

    let startIndex = 0;
    let matchIndex;

    while ((matchIndex = buffer.indexOf(delimiterBuffer, startIndex)) !== -1) {
        const chunk = buffer.slice(startIndex, matchIndex);
        result.push(chunk);
        startIndex = matchIndex + delimiterBuffer.length;
    }

    const remaining = buffer.slice(startIndex);
    if (remaining.length > 0) {
        result.push(remaining);
    }

    return result;
}

function joinBuffers(buffers) {
    const totalLength = buffers.reduce((acc, buffer) => acc + buffer.length, 0);
    const result = Buffer.allocUnsafe(totalLength);

    let offset = 0;

    buffers.forEach(buffer => {
        buffer.copy(result, offset);
        offset += buffer.length;
    });

    return result;
}

const statusCodeTexts = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",

    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    208: "Already Reported",
    226: "IM Used",

    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    306: "unused",
    307: "Temporary Redirect",
    308: "Permanent Redirect",

    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not acceptable",
    407: "Proxy Authentification Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfable",
    417: "Expectation Failed",
    419: "I'm a teapot",
    421: "Misdirected Request",
    422: "Unprocessable Content",
    423: "Locked",
    424: "Failed Dependency",
    425: "Too Early",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",

    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",
    507: "Insufficient Storage",
    508: "Loop Detected",
    510: "Not Extended",
    511: "Network Authentication Required"
}

class httpRequest {
    host;
    headers;
    body;
    method;
    ip;
    ips;
    url;
    cookies;
}

class httpResponse {
    statusCode = 200;
    isOpen =  true;
    sentHeaders =  false;
    headers =  {};
    cookies =  {};

    #socket;
    #version;

    constructor(socket, version){
        this.#socket = socket;
        this.#version = version;
    }

    sendHeaders() {
        if (this.sentHeaders) {
            throw new Error(`Unable to send headers multiple times.`)
        }

        if (!statusCodeTexts[this.statusCode]) {
            throw new Error(`Invalid status code ${this.statusCode}.`);
        }

        if(Object.keys(this.cookies).length > 0 && !this.headers["set-cookie"]){
            let setCookie = ``;

            for(let [name, value] of Object.entries(this.cookies)){
                setCookie += `${encodeURIComponent(name)}=${encodeURIComponent(value.value)}; SameSite=${value.sameSite}; Path=${value.path}; `

                if(value.secure) setCookie += "Secure; ";
                if(value.httpOnly) setCookie += "HttpOnly; ";
                if(value.priority == "High") setCookie += "Priority=High; ";
                if(value.domain) setCookie += `Domain=${value.domain}; `;
                if(value.expires) setCookie += `Expires=${value.expires.toUTCString()}; `;
            }

            if (setCookie.endsWith('; ')) {
                setCookie = setCookie.slice(0, -2);
            }

            this.headers["Set-Cookie"] = setCookie;
        }

        let headersMessage = `${this.#version} ${this.statusCode} ${statusCodeTexts[this.statusCode]}\r\n`
        Object.keys(this.headers).forEach(header => {
            headersMessage += `${header.toLowerCase()}: ${this.headers[header]}\r\n`;
        })

        headersMessage += `\r\n`;
        this.#socket.write(headersMessage);
        this.sentHeaders = true;
    }

    sendFile(filePath) {
        fs.readFile(filePath, (err, data) => {
            if (err) {
                this.statusCode = 500;
                return this.send(err.name + " " + err.message);
            }

            this.send(data);
        })
    }

    send(message){
        if (!this.isOpen) {
            throw new Error("Unable to send message after socket closed.")
        }

        if (!this.sentHeaders){
            this.sendHeaders()
        }

        if (message){
            this.#socket.write(message);
        }

        this.#socket.end();
    }

    stream = new stream.Writable({
        write: (chunk, encoding, callback) => {
            if (!this.isOpen) {
                throw new Error("Unable to send message after socket closed.");
            }

            if (!this.sentHeaders) {
                this.sendHeaders();
            }

            this.#socket.write(chunk, encoding);
            callback();
        },

        final: (callback) => {
            if (!this.isOpen) {
                throw new Error("Unable to send message after socket closed.");
            }

            if (!this.sentHeaders) {
                this.sendHeaders();
            }

            this.isOpen = false;
            this.#socket.end();
            callback();
        },
    });

    end() {
        if (!this.isOpen) {
            throw new Error("Unable to send message after socket closed.")
        }

        if (!this.sentHeaders)
        this.sendHeaders()

        this.isOpen = false;
        this.#socket.end();
    }
}

class cookie {
    value;
    secure;
    httpOnly;
    priority;
    domain;
    path;
    sameSite;
    expires;
}

class httpServer {
    #tcpServer;
    #middleware = [];
    #listeners = {
        GET: {},
        POST: {},
        DELETE: {},
        HEAD: {},
        PUT: {},
        PATCH: {},
        OPTIONS: {},
    };

    trustProxy = false;

    constructor() {
        this.#tcpServer = net.createServer(this.#handleSocket.bind(this))
    }

    #handleSocket(socket) {
        socket.on("data", (message) => {
            this.#handleSocketMessage(socket, message)
        })

        socket.on("error", socket.end)
    }

    #handleSocketMessage(socket, message) {
        let lines = message.toString().split("\n").map((v) => v.trimEnd())

        let requestLine = lines.shift()
        let hostLine = lines.shift()
        let charactersSkipped = 1 + requestLine.length + 2 + hostLine.length + 2;

        let requestData = requestLine.split(" ")
        let hostData = hostLine.split(" ")

        let method = requestData[0]
        let directory = requestData[1]
        let version = requestData[2]
        let host = hostData[1]
        let headers = {}

        if (version !== "HTTP/1.1") {
            return socket.end();
        }

        for (let line of lines) {
            if (line.trim().length == 0) {
                break;
            }

            charactersSkipped += line.length + 2;
            line = line.split(": ")
            headers[line.shift().toLowerCase()] = line.join(": ")
        }

        let body = message.subarray(charactersSkipped, message.length)
        let ips = {
            socket: socket.remoteAddress,
            client: socket.remoteAddress,
            proxy: ""
        }

        if (headers["x-forwarded-for"] && this.trustProxy) {
            let proxies = headers["x-forwarded-for"].split(", ")

            ips.client = proxies.shift();
            ips.proxy = proxies.shift();
        }

        let cookies = {}

        if(headers["cookie"]){
            let cookiesRaw = headers["cookie"].split("; ")
            let lastCookie;

            for(let cookieRaw of cookiesRaw){
                let [name, value] = cookieRaw.split("=")
                name = decodeURIComponent(name)

                if(name == "expires"){
                    if(!cookies[lastCookie]) continue;

                    cookies[name].expires = new Date(value);
                } else if(name == "Secure"){
                    if(!cookies[lastCookie]) continue;

                    cookies[name].secure = true;
                } else if(name == "HttpOnly"){
                    if(!cookies[lastCookie]) continue;

                    cookies[name].httpOnly = true;
                } else if(name == "Domain"){
                    if(!cookies[lastCookie]) continue;

                    cookies[name].domain = value;
                } else if(name == "Path"){
                    if(!cookies[lastCookie]) continue;

                    cookies[name].path = value;
                } else if(name == "SameSite"){
                    if(!cookies[lastCookie]) continue;

                    cookies[name].sameSite = value;
                } else if(name == "Priority"){
                    if(!cookies[lastCookie]) continue;

                    cookies[name].priority = value;
                } else {
                    cookies[name] = new cookie();
                    cookies[name].value = decodeURIComponent(value);
                    cookies[name].secure = false;
                    cookies[name].httpOnly = false;
                    cookies[name].priority = "";
                    cookies[name].domain = "";
                    cookies[name].path ="/";
                    cookies[name].sameSite = "Lax";
                    cookies[name].expires = new Date(0);

                    lastCookie = name;
                }
            }
        }

        let response = new httpResponse(socket, version);
        let request = new httpRequest();

        request.body = body;
        request.cookies = cookies;
        request.headers = headers;
        request.ips = ips;
        request.ip = ips.client;
        request.method = method;
        request.url = directory;
        request.host = host;

        callNextMiddleware.bind(this)(0);
        function callNextMiddleware(index) {
            if (!this.#middleware[index]) {
                if (this.#listeners[method]) {
                    let listener = this.#listeners[method][directory];
                    if(listener){
                        listener(request, response)
                    } else {
                        let listeners = Object.keys(this.#listeners[method]);

                        for(let listener of listeners){
                            if(!listener.includes("*")) continue;
                            let listenerMatch = wcmatch(listener)

                            if(listenerMatch(directory)){
                                this.#listeners[method][listener](request, response)
                                break;
                            }
                        }
                    }
                }

                return;
            }

            this.#middleware[index](request, response, () => callNextMiddleware.bind(this)(index + 1))
        }
    }

    get(name, func) {
        this.#listeners.GET[name] = func;
    }

    post(name, func) {
        this.#listeners.POST[name] = func;
    }

    put(name, func) {
        this.#listeners.PUT[name] = func;
    }

    delete(name, func) {
        this.#listeners.DELETE[name] = func;
    }

    head(name, func) {
        this.#listeners.HEAD[name] = func;
    }

    options(name, func) {
        this.#listeners.OPTIONS[name] = func;
    }

    patch(name, func) {
        this.#listeners.PATCH[name] = func;
    }

    use(func) {
        this.#middleware.push(func)
    }

    listen(port, hostname, onListen) {
        if (typeof port == "function") {
            onListen = port;
        }

        if (typeof hostname == "function") {
            onListen = hostname;
            hostname = "127.0.0.1";
        }

        this.#tcpServer.listen(port, hostname, onListen)
    }
}

const parsers = {
    form: (request, response, next) => {
        let ContentType = request.headers["content-type"]

        if (ContentType) {
            let [type, boundary] = ContentType.split(";")

            if (type == "multipart/form-data") {
                boundary = boundary.split("=")
                boundary.shift()
                boundary = `--${boundary.join("=")}`

                let body = splitBuffer(request.body, boundary)
                body.shift()
                //body.shift()
                body.pop()

                request.body = {}

                for (let key of body) {
                    let bodyLines = splitBuffer(key, `\r\n`)
                    let gotSpace = false;
                    let formPart = { headers: {}, data: null }
                    let lines = []

                    bodyLines.shift()

                    for (let bodyLine of bodyLines) {
                        if (gotSpace) {
                            lines.push(bodyLine)
                        } else {
                            if (bodyLine.toString().trim().length == 0) {
                                gotSpace = true;
                                continue;
                            }

                            let header = bodyLine.toString().split(": ")
                            formPart.headers[header.shift()] = header.join()
                        }
                    }

                    let ContentDisposition = formPart.headers["Content-Disposition"];
                    if(!ContentDisposition) continue;

                    formPart.data = joinBuffers(lines)
                    if (!ContentDisposition.includes(`filename="`)) {
                        formPart.data = parseString(formPart.data.toString());
                    }

                    let nameHeader = ContentDisposition.split("; ")
                                    .filter((v) => v.startsWith(`name="`))[0]
                                    .split(`name="`)[1].split(`"`);
                                    
                    nameHeader.pop()
                    nameHeader = nameHeader.join(`"`)
                
                    request.body[nameHeader] = formPart.data
                }
            }

            if(type == "application/x-www-form-urlencoded"){
                const pairs = request.body.toString().trim().split('&');
                const result = {};
              
                pairs.forEach((pair) => {
                  const [key, value] = pair.split('=').map(decodeURIComponent);
                  result[key] = parseString(value);
                });
              
                request.body = result;
            }
        }

        next()
    },
    json: (request, response, next) => {
        let ContentType = request.headers["content-type"]

        if (ContentType == `application/json`) {
            try {
                request.body = JSON.parse(request.body.toString());
            } catch(err){
                request.body = null;
            }
        }

        next()
    }
}

module.exports = { httpServer, parsers, cookie };