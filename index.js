const express = require('express');
const mysql = require('mysql');
const util = require('util'); // Para convertir en promesas los queries a la db que si no funcionan como callbacks
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();

const jwt = require('jsonwebtoken'); // Para generar los jwt para identificar las sessiones iniciadas
const bcrypt = require('bcrypt'); // Para encriptar contrasenas de las sessiones para la db
const unless = require('express-unless'); // Para verificar el jwt en todos los casos EXEPTO cuando el usuario se registra o logea

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json()); // Para pasar todo lo que venga en JSON en los requests a objeto automaticamente
app.use(express.urlencoded({ extended: true })); // Para pasar a objeto las variabes de los queries
app.use(cors());

// Sesion ///////////////////////////////////

const auth = (req, res, next) => {
    try {
        let token = req.headers['authorization'];
        if (!token) {
            throw new Error("No estas logueado");
        }
    
        token = token.replace('Bearer ','');
    
        jwt.verify(token, 'Secret', (err, user) => {
            if(err) {
                throw new Error("Token invalido");
            }
        });
        next();
    } catch (e) {
        res.status(403).send({mensaje: e.message});
    }
}

auth.unless = unless;

app.use(auth.unless({
    path: [
        {url: '/register', methods: ['POST']},
        {url: '/login', methods: ['POST']}
    ]
    })
);

/////////////////////////////



var conn = mysql.createConnection(
    {
        host: process.env.HOST,
        user: process.env.USER,
        password: process.env.PW,
        database: process.env.DB
    }
);


let qy;

/*
conn.connect((err) => {
    if (err) throw err;
    console.log("Connected to mysql");
    conn.query("CREATE DATABASE IF NOT EXISTS "+dbName+";", async function (err, result) {
        if (err) throw err;
        

        conn = mysql.createConnection(
            {
                host: 'localhost',
                user: 'root',
                password: '',
                database: dbName
            }
        );
*/
conn.connect(async (err) => {
    if(err) {
        console.log(err);
         return;
    }
    console.log("Connected to database");
    try {
        qy = util.promisify(conn.query).bind(conn);

        let table1query = "CREATE TABLE IF NOT EXISTS directorio "+
                            "(nombre VARCHAR(50) NOT NULL, apellido VARCHAR(50) "+
                            "NOT NULL, id INT AUTO_INCREMENT PRIMARY KEY );";
    
        let table2query = "CREATE TABLE IF NOT EXISTS telefonos "+
                            "(telefono VARCHAR(50) NOT NULL,"+
                            " tel_id INT AUTO_INCREMENT PRIMARY KEY,"+
                            " dir_id INT,"+
                            " FOREIGN KEY(dir_id) REFERENCES directorio(id) ON DELETE CASCADE);";
    
        let usuerTableQuery = "CREATE TABLE IF NOT EXISTS usuarios "+ 
                                  "(user VARCHAR(50) NOT NULL UNIQUE, "+
                                  "password VARCHAR(100) NOT NULL, "+
                                  "email VARCHAR(50) NOT NULL, "+
                                  "id INT AUTO_INCREMENT PRIMARY KEY);";
            
        let table1 = await qy(table1query);
        console.log("Table 1 created");
        let table2 = await qy(table2query);
        console.log("Table 2 created");
        let table3 = await qy(usuerTableQuery);
        console.log("Users table created");
    
    } catch(e){
        console.log(e.message);
    }
 
});


// Autenticacion
// Paso 1 Registracion
app.post('/register', async (req, res) => {
    try {
        if (!req.body.user || !req.body.password || !req.body.email) {
            throw new Error("No se enviaron todos los datos requeridos");
        }
        
        let result = await qy("SELECT * FROM usuarios WHERE user = ?;",[req.body.user]);
        if (result.length > 0) {
            throw new Error("Ya existe un usuario con ese nombre");
        }

        const pwCrypt = await bcrypt.hash(req.body.password, 10);

        result = await qy("INSERT INTO usuarios (user, password, email) VALUES (?, ?, ?);",[req.body.user, pwCrypt, req.body.email]);

        res.send({mensaje: "Se registró correctamente"});

    } catch (e) {
        res.status(404).send({mensaje: e.message});
    }
});
// Paso 2 Log In
app.post('/login', async (req, res) => {
    try {
        if (!req.body.user || !req.body.password) {
            throw new Error("No se enviaron todos los datos requeridos");
        }
        
        const pwCrypt = await bcrypt.hash(req.body.password, 10);

        let result = await qy("SELECT * FROM usuarios WHERE user = ?;",[req.body.user]);
        if (result.length == 0) {
            throw new Error("El nombre de usuario o contraseña son incorrectos");
        }
        console.log(result[0]);
        console.log(pwCrypt);
        if (!bcrypt.compareSync(req.body.password, result[0].password)) {
            throw new Error("El nombre de usuario o contraseña son incorrectos");
        }

        const tokenData = {
            usuario: result[0].user,
            email: result[0].email,
            id: result[0].id
        }

        const token = jwt.sign(tokenData, 'Secret', {
            expiresIn: 60*60 // expires in 1h
        });

        res.send({token: token});

    } catch (e) {
        res.status(404).send({mensaje: e.message});
    }
});


// POST Requests /////////////////////////////////////////////////////////

/* POST/contact receives {nombre: string, apellido: string, telefono:[]}
 * returns {id: int, nombre: string, apellido: string, telefono: []}
*/
app.post('/contact', async function(req, res) {
    
    let apellido = req.body.apellido.toUpperCase();
    let nombre = req.body.nombre.toUpperCase();
    let response = {};

    let query = `SELECT * FROM directorio WHERE nombre = "${nombre}" AND apellido = "${apellido}";`;
    
    let result = await qy(query);
    
    if (result.length != 0) {

        response.error = "El contacto que intentó crear ya existe.";

        res.send(response);
        return;
    }

    query = `INSERT INTO directorio (nombre, apellido) VALUES ("${nombre}", "${apellido}")`;

    result = await qy(query);
    let id = result.insertId; // Save contact id

    let keys =  Object.keys(req.body);

    for (tel in req.body.telefono) {
        query = `INSERT INTO telefonos (dir_id, telefono) VALUES ("${id}", "${req.body.telefono[tel]}")`;
        result = await qy(query);
    }

    response.id = id; // Send contact id to front end
    for (let key in req.body) {
        response[key] = req.body[key];    
    }

    res.send(response);
});


// GET Requests /////////////////////////////////////////////////////////


/* GET/contact/search / Search contacts based on name (string) and apellido (sting)
 * Returns array of contacts as JSONs
*/
app.get('/contact/search', async function(req, res) {

    try {

        let query = "SELECT d.id, d.nombre, d.apellido, t.telefono FROM directorio d JOIN telefonos t ON d.id = t.dir_id";

        if (req.query.nombre || req.query.apellido) {
            query += " WHERE";

            if (req.query.nombre) {
                query += " UPPER(d.nombre) LIKE '"+req.query.nombre.toUpperCase()+"%'";
            }

            if (req.query.nombre && req.query.apellido) {
                query += " AND";
            }

            if (req.query.apellido) {
                query += " UPPER(d.apellido) LIKE '"+req.query.apellido.toUpperCase()+"%'";
            }
        }

        query += ";";
        
        let result = await qy(query);

        if (result.length == 0) {
            res.send({mensaje: "No se encontraron registros"});
            res.send(response);
            return;
        }

        res.send(result);

    } catch (e) {
        res.status(404).send({mensaje: e.message});
    }
    
    
});

// GET/contact/:id returns {id: int, nombre: string, apellido: string, telefono1: [+()0-9], telefono2: [+()0-9], ... }

app.get('/contact/:id', async function(req, res) {
    try {
        let response = {};

    let query = "SELECT id, nombre, apellido FROM directorio WHERE id = ?;";

        let result = await qy(query, [req.params.id]);

    if (result.length == 0) {
        res.send({mensaje: "No se encontraron registros"});
        return;
    } else {
        response = result[0];
        query = "SELECT telefono FROM telefonos WHERE dir_id = ?;";
        result = await qy(query, [req.params.id]);
        response.telefono = [];
        for (tel in result) {
            response.telefono.push(result[tel].telefono);
        }
        
    }

    res.send(response);

    } catch (e) {
        res.status(404).send({mensaje: e.message});
    }
    
    
});


// DELETE RRequests /////////////////////////////////////////////////////////

app.delete('/contact/:id', async function(req, res) {

    res.send("Pending");

});

// ALL OTHER ROUTES //////////////////////////

app.all('*', async function(req, res) {

    res.send({mensaje: "Ruta no es parte de la API"});
});

// LISTEN /////////////////////////////////////////////////////////////////

app.listen(port, function(){
    console.log("Express has iniciated in port ",port,".");
});