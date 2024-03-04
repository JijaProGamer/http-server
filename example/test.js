let httpServer = require("../index.js");
let fs = require("fs")
let path = require("path")

let server = new httpServer.httpServer()

server.listen(8500, "127.0.0.1", () => {
    console.log("bomba listening")
})

server.use(httpServer.parsers.json)
server.use(httpServer.parsers.form)

server.get("/", (req, res) => {
    console.log(req)
    res.sendFile(path.join(__dirname, "/example.html"));
})

server.get("/*", (req, res) => {
    res.statusCode = 200;
    res.send("testing matches");
})

server.post("/form", (req, res) => {
    console.log(req)

    res.statusCode = 201;
    res.send();
})

/*server.get("/", (req, res) => {
    let videoFilePath = path.join(__dirname, "/BigBuckBunny.mp4")

    res.headers = {
        ['Content-Type']: 'video/mp4',
        ['Content-Length']:  fs.statSync(videoFilePath).size,
        ['Accept-Ranges']: 'bytes',
        ['Content-Disposition']: 'inline; filename=video.mp4'
    }

    // stupid way

    //res.sendFile(videoFilePath);

    // smart way

    fs.createReadStream(videoFilePath).pipe(res.stream);
})*/