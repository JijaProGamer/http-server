let httpServer = require("./index.js");
let fs = require("fs")
let path = require("path")

let server = new httpServer.httpServer()

server.listen(8500, "127.0.0.1", () => {
    console.log("bomba listening")
})

server.use(httpServer.parsers.form)

server.get("/", (req, res) => {
    //res.send(Buffer.from("test data"))

    /*fs.readFile(path.join(__dirname, "/example.html"), "utf-8", (err, data) => {
        if(err){
            res.statusCode = 500;
            return res.send();
        }

        res.send(data);
    })*/

    res.sendFile(path.join(__dirname, "/example.html"));
})

server.post("/form", (req, res) => {
    console.log(req)

    res.statusCode = 201;
    res.send();
})