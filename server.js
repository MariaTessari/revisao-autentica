import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "./db.js"

const app = express()
const JWT_SECRET = "sua_chave_super_segura";

app.use(
    cors({
        credentials: true
    })
)

app.use(express.json())
app.use(cookieParser())

function autenticarToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ mensagem: "Acesso negado. Faça login" })
    }

    try {
        const usuario = jwt.verify(token, JWT_SECRET);
        req.usuario = usuario;
        next();
    } catch (error) {
        return res.status(403).json({ mensagem: "Token inválido ou expirado" })
    }
}

app.post("/cadastrar", async (req, res) => {
    const { email, senha, cpf } = req.body;

    try {
        const senhaHash = await bcrypt.hash(senha, 10);
        const cpfHash = await bcrypt.hash(cpf, 10);

        const query =
            "INSERT INTO cliente(email, senha, cpf) VALUES ($1, $2, $3) RETURNING id email"
        const values = [email, senhaHash, cpfHash];

        const resultado = await db.query(query, values);

        return res.status(201).json({
            mensagem: "Cliente cadastrado com sucesso!",
            cliente: resultado.rows[0],
        });
    } catch (error) {
        return res.status(500)
        .json({mensagem: "Erro ao cadastrar cliente.", erro: error.message})
    }
});

app.post("/login", async (req, res) =>{
    const { email, senha } = req.body;

    try{
        const query = "SELECT * FROM cliente WHERE email = $1";
        const resultado = await db.query(query, [email]);
        const cliente = resultado.rows[0];

        if(!cliente) {
            return res.status(401).json({mensagem: "Credenciais inválidas"});
        }

        const senhaValida = await bcrypt.compare(senha, cliente.senha);
        if(!senhaValida) {
            return res.status(401).json({ mensagem: "Credenciais inválidas"});
        }

        const token = jwt.sign(
            { id: cliente.id, email: cliente.email },
            JWT_SECRET,
            { expiresIn: "1h"},
        );

        res.cookie("token", token, {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            maxAge: 3600000,
    });

        return res.json({
            mensagem: "Login realizado com sucesso",
            cliente: { id:cliente.id, email: cliente.email },
        });
    } catch (error) {
        return res
        .status(500)
        .json({mensagem: "Erro no servidor.", erro: error.message })
    }
});

app.get("/perfil", autenticarToken, async (req, res) => {
    try{
        const query = "SELECT id, email FROM cliente WHERE id = $1";
        const resultado = await db.query(query, [req.usuario.id]);

        return res.json({
            mensagem: "Dados acessados com sucesso via Cookie!",
            cliente: resultado.rows[0],
        });
    } catch (error){
        return res.status(500).json({ mensagem: "Erro ao buscar perfil."})
    }
});

app.post("/logout", (req, res)=>{
    res.clearCookie("token");
    return res.json({ menagem: "Logout realizado com sucesso!"})
});

app.listen(3000, ()=>{
    console.log("Servidor rodando em http://localhost:3000");
});