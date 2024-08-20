import express, {NextFunction, Request, Response} from "express"
import knex from "knex"
import dotenv from "dotenv"
import bcrypt from "bcryptjs"
import jwt, { JwtPayload } from "jsonwebtoken"
import cors from "cors"
import multer from "multer"
import path from "path"
import {createServer} from "http"
import { Server, Socket } from "socket.io"

dotenv.config()

const server = express()
server.use(cors())
server.use(express.json())

const httpServer = createServer(server)
const io = new Server<ClientToServerEvents, ServerToClientEvents>(httpServer, {
  cors: {
    origin: "*",
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  }
})

//knex config
const db = knex({
    client: "mysql",
    connection: {
        host: "127.0.0.1",
        port: 3306,
        user: "root",
        password: process.env.MYSQL_SENHA,
        database: "selestial",
    },
    log: {
        warn(message) {},
        error(message) {},
        deprecate(message) {},
        debug(message) {},
    },
});

//multer config
server.use(express.static(path.resolve("public")));
const storage = multer.diskStorage({
  destination: async function (req, file, cb) {
    return cb(null, "./public/images");
  },
  filename: function (req, file, cb) {
    return cb(null, `${Date.now()}_${file.originalname}`);
  },
});

const uploadImg = multer({ storage });

interface ServerToClientEvents {
  serverMsg: (data: {msg: string, room: string}) => void,
  novaSala: (data: {newRoom: string, createdById: string, idProfissional: number}) => void,
  novaMensagem: (data: {novoHistorico: string}) => void,
  mudStatus: (data: {status: string, id: number}) => void,
  salaEncerrada: (data: {msg: string, idSala: string}) => void,
  precoTempoServMsg: (data: {preco: number, tempo: number}) => void,
  erroMsg: (data: {erroMsg: string}) => void,
  clienteChamando: (data: {idProfissional: number, nomeCliente: string, idCliente: number}) => void,
  respostaAtendente: (data: {msg: string, idCliente: number, idProfissional: number}) => void,
  atualizarAdm: () => void,

}


interface ClientToServerEvents {
  acionaMudStatus: (data: {status: string, id: number}) => void,
  clientMsg: (data: {msg: string, room: string}) => void,
  adicionarNaSala: (data: {room: string}) => void,
  tempoPreco: (data: {tempo: number, preco: number, room: string}) => void,
  chamarAtendente: (data: {idProfissional: number, nomeCliente: string, idCliente: number}) => void,
  respostaChamarAtendente: (data: {msg:  string, idCliente: number, idProfissional: number}) => void,
  comprouSaldoDentroConsulta: (data: {room: string}) => void,
  sairDaSala: (data: {room: string}) => void

}

io.on("connection", (socket: Socket<ClientToServerEvents, ServerToClientEvents>) => {
  socket.on("chamarAtendente", (data) => {
    console.log("to enviando o cliente chamando")
    console.log(data.idProfissional)
    io.to(data.idProfissional.toString()).emit("clienteChamando", {idProfissional: data.idProfissional, idCliente: data.idCliente, nomeCliente: data.nomeCliente})
  })

  socket.on("respostaChamarAtendente", (data: {msg: string, idCliente: number, idProfissional: number}) => {

    console.log("ta vindo aqui no resposta")
    io.to(data.idProfissional.toString()).emit("respostaAtendente", {msg: data.msg, idCliente: data.idCliente, idProfissional: data.idProfissional})
  })

  socket.on("adicionarNaSala", (data: {room: string}) => {
    socket.join(data.room)
    console.log("a sala é " + data.room)
  })

  socket.on("clientMsg", (data: {msg: string, room: string}) => {
    console.log("mensagem")
    console.log(data.msg)
    console.log("sala")
    console.log(data.room)
  })

  socket.on("sairDaSala", (data) => {
    socket.leave(data.room)
  })

  socket.on("clientMsg", async (data: {msg: string, room: string}) => {
    console.log("CHEGOU MENSAGEM DO CLIENTE")
    console.log(data.msg)
    console.log(data.room)

    if(Number(data.room) > 0){
      if(data.msg == ""){
        //Se a msg vier vazia, só retorna o historico
        const arrNovoHistorico = await db("salas").select("historico").where({id_profissional: data.room})
        console.log("sala: " + data.room)
        if(arrNovoHistorico){
          if(arrNovoHistorico[0]){
            const novoHistorico = arrNovoHistorico[0].historico
            io.sockets.to(data.room).emit("novaMensagem", {novoHistorico})
          }else{
            io.sockets.to(data.room).emit("novaMensagem", {novoHistorico: ""}) 
          }
        }else{
          io.sockets.to(data.room).emit("novaMensagem", {novoHistorico: ""})
        }
      }else{
        //Caso venha uma mensagem de fato
        io.sockets.to(data.room).emit("serverMsg", data)
        const arrTextoAtual = await db("salas").select("historico").where({id_profissional: data.room}) 
        let novoHistorico
        if(arrTextoAtual[0] !== undefined){
          if(arrTextoAtual[0].historico){
            novoHistorico = arrTextoAtual[0].historico + "||n||" + data.msg
          }else{
            novoHistorico = "" + "||n||" + data.msg
          }
        }else{
          novoHistorico = "" + "||n||" + data.msg
        }
        console.log("sala q mandaram do front: " + data.room)
        await db("salas").where({id_profissional: data.room}).update({historico: novoHistorico}) 
        const arrNovoHistorico = await db("salas").select("historico").where({id_profissional: data.room})
        console.log(arrNovoHistorico)
        if(arrNovoHistorico){
          novoHistorico = arrNovoHistorico[0].historico
        }
        io.sockets.to(data.room).emit("novaMensagem", {novoHistorico})
      }
    }


  })

})




async function confereTokenAtendente(req: Request, res: Response, next: NextFunction){    
  const auth = req.headers['authorization']

  if(!auth){
      return res.json({codigo: 400, detalhes: "não foi enviado authorization pelo usuário"})
  }

  const [type, token] = auth.split(' ')


  if(type !== 'Bearer'){
      return res.json({codigo: 400, detalhes: "tipo de autorização diferente de Bearer"})
  }

  if(!process.env.SECRET_ATENDENTE){
      return res.json({codigo: 500, detalhes: "falha ao procurar secret no servidor"})
  }

  try{
      const payload = jwt.verify(token, process.env.SECRET_ATENDENTE)
      if(typeof payload == 'string'){
          return res.json({codigo: 500, detalhes: "algo de errado com o servidor"})
      }
      
      const tokenDecod = tokenAtendenteDecodificado(req, res)

      
      if(tokenDecod.id == 0){
        return res.json({codigo: 200, detalhes: "ocorreu algum erro ao verificar o token"})
      }


      

      try{
        const arrSalasProf = await db("salas").select().where({id_profissional: tokenDecod.id})

        if(arrSalasProf.length > 0){
          await db("profissionais").update({status: "ocupado"}).where({id: tokenDecod.id})
          io.sockets.emit("mudStatus", {status: "ocupado", id: tokenDecod.id})
        }else{
          await db("profissionais").update({status: "online"}).where({id: tokenDecod.id})
          io.sockets.emit("mudStatus", {status: "online", id: tokenDecod.id})
        }

        next()
      }catch(err){
        return res.json({codigo: 500, detalhes: "erro ao setar status do atendente. Por favor, tente novamente"})
      }


  }catch(err){
      return res.json({codigo: 500, detalhes: "erro ao verificar o token jwt"})
  }
}


function confereTokenUsuario(req: Request, res: Response, next: NextFunction){    
  const auth = req.headers['authorization']
  console.log("authorization usuario")
  console.log(auth)

  if(!auth){
      return res.json({codigo: 400, detalhes: "não foi enviado authorization pelo usuário"})
  }

  const [type, token] = auth.split(' ')


  if(type !== 'Bearer'){
      return res.json({codigo: 400, detalhes: "tipo de autorização diferente de Bearer"})
  }

  if(!process.env.SECRET_USUARIO){
      return res.json({codigo: 500, detalhes: "falha ao procurar secret no servidor"})
  }

  try{
      const payload = jwt.verify(token, process.env.SECRET_USUARIO)
      if(typeof payload == 'string'){
          return res.json({codigo: 500, detalhes: "algo de errado com o servidor"})
      }

      next()
  }catch(err){
      return res.json({codigo: 500, detalhes: "erro ao verificar o token jwt"})
  }
}


function confereTokenAdmGeral(req: Request, res: Response, next: NextFunction){    
  const auth = req.headers['authorization']

  if(!auth){
      return res.json({codigo: 400, detalhes: "não foi enviado authorization pelo usuário"})
  }

  const [type, token] = auth.split(' ')


  if(type !== 'Bearer'){
      return res.json({codigo: 400, detalhes: "tipo de autorização diferente de Bearer"})
  }

  if(!process.env.SECRET_ADM){
      return res.json({codigo: 500, detalhes: "falha ao procurar secret no servidor"})
  }

  try{
      const payload = jwt.verify(token, process.env.SECRET_ADM)
      if(typeof payload == 'string'){
          return res.json({codigo: 500, detalhes: "algo de errado com o servidor"})
      }

      next()
  }catch(err){
      return res.json({codigo: 500, detalhes: "erro ao verificar o token jwt"})
  }
}



function tokenAtendenteDecodificado(req: Request, res: Response): {id: number, email: string, iat: number, exp: number} | JwtPayload{
  const auth = req.headers['authorization']
  if(!auth){
    return res.json(["erro", "autorização negada, por favor tente se logar novamente"])
  }
  const [type, token] = auth.split(' ')

    try{
      const tokenDecodificado = jwt.verify(token, process.env.SECRET_ATENDENTE || "")
      if(typeof tokenDecodificado == "string"){
        return {id: 0, email: "", iat: 0, exp: 0}
      }else{
        return tokenDecodificado
      }
    }catch(err){
      return {id: 0, email: "", iat: 0, exp: 0}
    }
}

function tokenUsuarioDecodificado(req: Request, res: Response): {id: number, email: string, iat: number, exp: number} | JwtPayload{

  const auth = req.headers['authorization']
  if(!auth){
    return res.json(["erro", "autorização negada, por favor tente se logar novamente"])
  }
  const [type, token] = auth.split(' ')

  try{
    const tokenDecodificado = jwt.verify(token, process.env.SECRET_USUARIO || "")
    if(typeof tokenDecodificado == "string"){
      return {id: 0, email: "", iat: 0, exp: 0}
    }else{
      return tokenDecodificado
    }
  }catch(err){
    return {id: 0, email: "", iat: 0, exp: 0}
  }
}

function tokenAdmGeralDecodificado(req: Request, res: Response): {id: number, email: string, iat: number, exp: number} | JwtPayload{

  const auth = req.headers['authorization']
  if(!auth){
    return res.json(["erro", "autorização negada, por favor tente se logar novamente"])
  }
  const [type, token] = auth.split(' ')

  try{
    const tokenDecodificado = jwt.verify(token, process.env.SECRET_ADM_GERAL || "")
    if(typeof tokenDecodificado == "string"){
      return {id: 0, email: "", iat: 0, exp: 0}
    }else{
      return tokenDecodificado
    }
  }catch(err){
    return {id: 0, email: "", iat: 0, exp: 0}
  }
}



server.get("/confereTokenAdmGeral", confereTokenAdmGeral, (req: Request, res: Response) => {
  res.json({codigo: 200, detalhes: "acesso liberado"})
})

server.get("/confereTokenAtendente", confereTokenAtendente, async (req: Request, res: Response) => {

  const tokenDecod = tokenAtendenteDecodificado(req, res)

  if(!tokenDecod.id){
    return res.json({codigo: 500, detalhes: "erro ao decodificar o token do atendente. Por favor tente novamente. Caso persista é recomendado que faça login novamente."})
  }

  try{
    const arrInfosAtendente = await db("profissionais").select().where({id: tokenDecod.id})
    const arrTotalArrecadado = await db("historicossalvos").sum("precoReal").where({id_profissional: tokenDecod.id})
    if(arrTotalArrecadado.length > 0){
      arrInfosAtendente[0].totalArrecadado = arrTotalArrecadado[0]["sum(`precoReal`)"]
    }else{
      arrInfosAtendente[0].totalArrecadado = 0
    }


    const arrIdsBaralhosBruto = await db("trabalhos").select("id")
    if(!arrIdsBaralhosBruto || !(arrIdsBaralhosBruto[0].id)){
      return res.json(["erro", "ocorreu um erro ao buscar dados no banco de dados, por favor, tente novamente"])
    }
  
    let arrBaralhos = []
  
    for(let i = 0; i < arrIdsBaralhosBruto.length; i++){
      const idAtual = arrIdsBaralhosBruto[i].id
  
      const arrNome = await db("trabalhos").select("trabalho").where({id: idAtual})
      if(!arrNome || !(arrNome[0].trabalho)){
        return res.json(["erro", "ocorreu um erro ao buscar dados no banco de dados, por favor, tente novamente"])
      }
      const nome = arrNome[0].trabalho
  
      const arrUrlsBruto = await db("urlstrabalhos").select("url").where({id_trabalho: idAtual})
      if(!arrUrlsBruto || !(arrUrlsBruto[0].url)){
        return res.json(["erro", "ocorreu um erro ao buscar dados no banco de dados, por favor, tente novamente"])
      }
  
      let arrUrls = []
  
      for(let i = 0; i < arrUrlsBruto.length; i++){
        const url = arrUrlsBruto[i].url
        arrUrls.push(url)
      }
  
      arrBaralhos.push({nomeBaralho: nome, urlsCartas: arrUrls})
    }  

    return res.json({codigo: 200, detalhes: "acesso liberado", res: arrInfosAtendente[0], arrBaralhos})
  }catch(err){
    return res.json({codigo: 500, detalhes: "ocorreu um erro ao pegar os valores do banco de dados"})
  }

})

server.get("/confereTokenUsuario", confereTokenUsuario, (req: Request, res: Response) => {
  res.json({codigo: 200, detalhes: "acesso liberado",})
})

server.post("/cadastrarAdm", (req: Request, res: Response) => {

    const {email, nome} = req.body

    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(email + "@123", salt, async function(err, hash) {
            if(err){
                res.json(["erro", "não foi possível cadastrar a senha"])
                return
            }else{
                //usuarios tem o email como primary key e os outros como foreign, logo tem q criar em usuarios primeiro pra dps poder criar nos outros
                await db('loginadmgeral').insert({email, hash, id_admGeral: 1})
                await db("admgeral").insert({nome, email}) 
                return res.json(["sucesso", "cadastro feito com sucesso"])
            }
        });
      });

})

server.post("/cadastrarUsuario", async (req: Request, res: Response) => {
  const {email, senha, nome, dataNas} = req.body

  try{
    const arrEmailsCadastrados = await db("usuarios").select("email")
    if(arrEmailsCadastrados.every(item => item.email !== email)){

      await db("usuarios").insert({nome: nome, email: email, dataNas})
      const arrIdUsuAtual = await db("usuarios").select("id").where({email: email})

      bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(senha, salt, async function(err, hash) {
            if(err){
                res.json({codigo: 500, detalhes: "não foi possível cadastrar a senha"})
                return
            }else{
                //usuarios tem o email como primary key e os outros como foreign, logo tem q criar em usuarios primeiro pra dps poder criar nos outros
                await db('loginusuario').insert({email: email, hash, id_usuario: arrIdUsuAtual[0].id}) 
                return res.json({codigo: 200, detalhes: "cadastro realizado com sucesso"})
            }
        });
      });
    }else{
      return res.json({codigo: 401, detalhes: "esse email já está cadastrado"})
    }
  }catch(err){
    return res.json({codigo: 500, detalhes: "ocorreu um erro ao inserir os valores no banco de dados, por favor, tente novamente. Caso persista contate o suporte."})
  }
})


server.post("/login", async (req: Request, res: Response) => {
  
    const {email, senha, tipoLogin} = req.body
  
    if(!tipoLogin){
      return res.json({codigo: 400, detalhes: "não foi especificado o tipo de login"})
    }
  
    try{
  
      let secret = ""
      let loginBd = ""
      let tipoIdAtual = ""
  
      switch(tipoLogin){
        case "Atendente":
          loginBd = "loginatendentes"
          tipoIdAtual = "id_profissional"
          if(process.env.SECRET_ATENDENTE){
            secret = process.env.SECRET_ATENDENTE 
          }else{
            return res.json({codigo: 500, detalhes: "secret não encontrado"})
          }
          break
  
        case "Usuario":
          loginBd = "loginusuario"
          tipoIdAtual = "id_usuario"
          if(process.env.SECRET_USUARIO){
            secret = process.env.SECRET_USUARIO 
          }else{
            return res.json({codigo: 500, detalhes: "secret não encontrado"})
          }
          break
  
        case "Adm":
          loginBd = "loginadmgeral"
          tipoIdAtual = "id_admGeral"
          if(process.env.SECRET_ADM){
            secret = process.env.SECRET_ADM 
          }else{
            console.log("ta vindoaquiiiii")
            return res.json({codigo: 500, detalhes: "secret não encontrado"})
          }
      }
  
        let arrUser = await db(loginBd).where({email}).select()
  
        if(arrUser.length == 0){
            return res.status(401).json({codigo: 401, detalhes: "não foi encontrado usuário com o email enviado"})
            
        }
  
        bcrypt.compare(senha, arrUser[0].hash, async function(err, resp) {
            if(resp){
                try{
                    if(!secret){
                        res.json({codigo: 500, detalhes: "secret não encontrado no servidor"})
                    }else{
                        const token = jwt.sign({
                            id: arrUser[0][tipoIdAtual],
                            email: arrUser[0].email
                        }, secret, {expiresIn: "30d"})
                        if(token){
                            res.json({codigo: 200, token, detalhes: "sucesso"}) 
                        }else{
                            res.json({codigo: 500, detalhes: "problema na criação do token"})
                        }
                    }
                }catch(err){
                    res.json({codigo: 500, detalhes: "caiu no catch"})
                }
            }else{
                res.status(401).json({codigo: 401, detalhes: "senha errada"})
            }
        });
    }catch{
        res.status(400).json({codigo: 500, detalhes: "caiu no catch"})
    }
  
  })


  server.get("/pegarInfoUsuario", confereTokenUsuario, async (req: Request, res: Response) => {



    const tokenDecod = tokenUsuarioDecodificado(req, res)



    try{
      const arrInfoUsuario = await db("usuarios").select().where({id: tokenDecod.id})
      console.log(arrInfoUsuario[0])
      return res.json({codigo: 200, detalhes: "sucesso", res: arrInfoUsuario[0]})
    }catch(err){
      return res.json({codigo: 500, detalhes: "ocorreu algum erro ao pegar valores do banco de dados"})
    }


})


server.post("/confereSalas", confereTokenUsuario, async (req: Request, res: Response) => {
  //tem que conferir direto pelo status pq o cara pode ter setado ocupado mesmo estando sem sala pra ir no banheiro por exemplo

  const tokenDecod = tokenUsuarioDecodificado(req, res)
  const {idProfissional} = req.body

  if(tokenDecod.id == 0 || !idProfissional){
    return res.json({codigo: 500, detalhes: "ocorreu algum erro ao verificar o token"})
  }

  try{

    const arrStatusProfissional = await db("profissionais").select("status").where({id: idProfissional})

    if(arrStatusProfissional.length > 0){
      if(arrStatusProfissional[0].status == "online"){
        //tá disponível
        
        return res.json({codigo: 200, detalhes: "criar sala"})
      }else if(arrStatusProfissional[0].status == "ocupado"){
        const arrSalaCliente = await db("salas").select("idSala").where({id_cliente: tokenDecod.id, id_profissional: idProfissional})
        if(arrSalaCliente.length > 0){
          return res.json({codigo: 200, detalhes: "sala existente", res: arrSalaCliente[0].idSala})
        }else{
          return res.json({codigo: 200, detalhes: "profissional ocupado"})
        }
      }else{
        return res.json({codigo: 200, detalhes: "profissional não disponível"})
      }
    }else{
      return res.json({codigo: 500, detalhes: "ocorreu um erro ao pegar o status do atendente."})
    }

  }catch(err){
      return res.json({codigo: 500, detalhes: "ocorreu um erro ao conferir dados no banco de dados. Por favor, tente novamente"})
  }
})


  //cadastro profissional
  server.post("/addFotoProfissional", confereTokenAdmGeral, (req: Request, res: Response) => {

    uploadImg.single("imgProf")(req, res, async function (err) {
      if (err instanceof multer.MulterError) {
        // A Multer error occurred when uploading.
        res.json({codigo: 500, detalhes: "Ocorreu um erro no multer"})
        return
      } else if (err) {
        // An unknown error occurred when uploading.
        res.json({codigo: 500, detalhes: "ocorreu um erro inisperado no upload"})
        return
      }
  
      // Everything went fine.
      if(req.file?.filename){
        await db("profissionais").insert({foto: req.file.filename})
      }else{
        res.json({codigo: 500, detalhes: "ocorreu um erro no upload: não conseguiu achar req.file.filename"})
        return
      }
  
      //req.files[0].filename
      const arrId = await db("profissionais").max("id as id")
      console.log(arrId)
      res.json({codigo: 200, detalhes: "sucesso", res: arrId})
    })
  })

  server.post("/addInfosProfissional", confereTokenAdmGeral, async (req: Request, res: Response) => {
    const {nomeProf, emailProf, descricaoMenor, descricaoMaior, id, valorMin, percentualPro} = req.body
  
    try{
      await db.transaction(async (trx) => {
        const arrAtendente = await trx("profissionais").select().where({email: emailProf})
        if(arrAtendente.length > 0){
          return res.json({codigo: 400, detalhes: "email já cadastrado"})
        }else{

          await trx("profissionais").update({nome: nomeProf , email: emailProf, descricaoMenor, descricaoMaior, valorMin, percentualPro}).where({id})
          console.log("passou do primeiro")
      
          /*for(let i = 0; i < arrTrabalho.length; i++){
            let trabalhoAtual = arrTrabalho[i]
            const arrIdTrabalhoAtual = await db("trabalhos").select("id").where({trabalho: trabalhoAtual})
            const idTrabalhoAtual = arrIdTrabalhoAtual[0].id
            await db("reltrabprof").insert({id_trabalho: idTrabalhoAtual, id_profissional: id})
          }*/
      
          
          bcrypt.genSalt(10, function(err, salt) {
            let senhaAuto = emailProf + "@123"
            bcrypt.hash(senhaAuto, salt, async function(err, hash) {
                if(err){
                    await trx("profissionais").where(id).del()
                    return res.json({codigo: 500, detalhes: "não foi possível cadastrar a senha"})
                }else{
                    //usuarios tem o email como primary key e os outros como foreign, logo tem q criar em usuarios primeiro pra dps poder criar nos outros
                    await trx('loginatendentes').insert({email: emailProf, hash, id_profissional: id}) //A unica coisa que mudei foi a ordem desses doissssssssss
                    console.log("passou do segundo")
                  }
              });
          });
      
          const arrPro = await trx("profissionais").select().where({id})
          console.log("passou do terceiro")
          const arrLoginPro = await trx("profissionais").select().where({id_profissionais: id})//aqui ta errado de proposito
          console.log("passou do quarto")
          if(arrPro.length > 0 && arrLoginPro.length > 0){
            return res.json({codigo: 200, detalhes: "profissional cadastrado com sucesso"})
          }else{
            trx("profissionais").where({id}).del()
            console.log("passou do quinto")
            trx("loginatendentes").where({id_profissional: id}).del()
            console.log("passou do sexto")
            return res.json({codigo: 500, detalhes: "não foi possível cadastrar o profissional"})
          }

        }
      })
    

    }catch(err){
      return res.json({codigo: 500, detalhes: "catch"})
    }
  
  
  })


  server.post("/cadastrarProfissional", confereTokenAdmGeral, (req: Request, res: Response) => {



    uploadImg.single("imgProf")(req, res, async function (err) {

      const {nomeProf, emailProf, descricaoMenor, descricaoMaior, valorMin, percentualPro} = req.body
      console.log(req.body)
  
      console.log(emailProf)
      console.log( nomeProf)

  
      //req.files[0].filename



      try{


        
        await db.transaction(async (trx) => {

          if (err instanceof multer.MulterError) {
            // A Multer error occurred when uploading.
            res.json({codigo: 500, detalhes: "Ocorreu um erro no multer"})
            return
          } else if (err) {
            // An unknown error occurred when uploading.
            res.json({codigo: 500, detalhes: "ocorreu um erro inisperado no upload"})
            return
          }
      
          // Everything went fine.
          if(req.file?.filename){
            await trx("profissionais").insert({foto: req.file.filename})
          }else{
            res.json({codigo: 500, detalhes: "ocorreu um erro no upload: não conseguiu achar req.file.filename"})
            return
          }


          const arrId = await trx("profissionais").max("id as id")
          let id = 0
          if(arrId.length > 0){
            id = arrId[0].id
          }
          const arrAtendente = await trx("profissionais").select().where({email: emailProf})
          if(arrAtendente.length > 0){
            return res.json({codigo: 400, detalhes: "email já cadastrado"})
          }else{
  
            await trx("profissionais").update({nome: nomeProf , email: emailProf, descricaoMenor, descricaoMaior, valorMin: Number(valorMin), percentualPro: Number(percentualPro)}).where({id})
            console.log("passou do primeiro")
        
            /*for(let i = 0; i < arrTrabalho.length; i++){
              let trabalhoAtual = arrTrabalho[i]
              const arrIdTrabalhoAtual = await db("trabalhos").select("id").where({trabalho: trabalhoAtual})
              const idTrabalhoAtual = arrIdTrabalhoAtual[0].id
              await db("reltrabprof").insert({id_trabalho: idTrabalhoAtual, id_profissional: id})
            }*/
        
            
            bcrypt.genSalt(10, function(err, salt) {
              let senhaAuto = emailProf + "@123"
              bcrypt.hash(senhaAuto, salt, async function(err, hash) {
                  if(err){
                      await trx("profissionais").where(id).del()
                      return res.json({codigo: 500, detalhes: "não foi possível cadastrar a senha"})
                  }else{
                      //usuarios tem o email como primary key e os outros como foreign, logo tem q criar em usuarios primeiro pra dps poder criar nos outros
                      await trx('loginatendentes').insert({email: emailProf, hash, id_profissional: id}) //A unica coisa que mudei foi a ordem desses doissssssssss
                      console.log("passou do segundo")
                    }
                });
            });
        
            const arrPro = await trx("profissionais").select().where({id})
            console.log("passou do terceiro")
            const arrLoginPro = await trx("profissionais").select().where({id})
            console.log("passou do quarto")
            if(arrPro.length > 0 && arrLoginPro.length > 0){
              return res.json({codigo: 200, detalhes: "profissional cadastrado com sucesso"})
            }else{
              trx("profissionais").where({id}).del()
              console.log("passou do quinto")
              trx("loginatendentes").where({id_profissional: id}).del()
              console.log("passou do sexto")
              return res.json({codigo: 500, detalhes: "não foi possível cadastrar o profissional"})
            }
  
          }
        })
      
  
      }catch(err){
        console.log(err)
        return res.json({codigo: 500, detalhes: "catch"})
      }

    })
  })


  server.post("/cadastrarTrabalho", uploadImg.array("files"), async (req: Request, res: Response) => {
    const {novoTrabalho} = req.body

    let arrFilenames: string[] = [];

    (req.files as Array<Express.Multer.File>).map(
      (item: { filename: string }) => arrFilenames.push(item.filename)
    );

    try{
      let arrTrabalhos = await db("trabalhos").select("trabalho")
      if(arrTrabalhos.every(item => item.trabalho !== novoTrabalho)){
        await db("trabalhos").insert({trabalho: novoTrabalho})
        const arrIdNovoTrabalho = await db("trabalhos").select("id").where({trabalho: novoTrabalho})
        if(!arrIdNovoTrabalho || !(arrIdNovoTrabalho[0].id)){
          return res.json({codigo: 500, detalhes: "ocorreu um erro, por favor tente novamente"})
        }
        const idNovoTrabalho = arrIdNovoTrabalho[0].id
        arrFilenames.forEach(async (item, index) => {
          await db("urlstrabalhos").insert([
            {
              id_trabalho: idNovoTrabalho,
              url: item
            },
          ]);
        });

        return res.json({codigo: 200, detalhes: "Novo trabalho cadastrado com sucesso"})
      }
      return res.json({codigo: 400, detalhes: "baralho já cadastrado"})
    }catch(err){
        res.json({codigo: 500, detalhes: "ocorreu um erro ao cadastrar o novo trabalho"})
    }
})

server.get("/pegarInfoProfissionaisAberto", async (req: Request, res: Response) => {
  try{
    const arrInfoPros = await db("profissionais").select()
    console.log(arrInfoPros)
    res.json({codigo: 200, detalhes: "sucesso", res: arrInfoPros})
  }catch(err){
    res.json({codigo: 500, detalhes: "ocorreu um erro ao pegar as informações dos profissinais. Por favor, recarregue a página"})
  }
})

server.get("/minhasInfosAtendente", confereTokenAtendente, async (req: Request, res: Response) => {
  const tokenDecod = tokenAtendenteDecodificado(req, res)

  if(!tokenDecod.id){
    return res.json({codigo: 500, detalhes: "erro ao decodificar o token do atendente. Por favor tente novamente. Caso persista é recomendado que faça login novamente."})
  }

  try{
    const arrInfosAtendente = await db("profissionais").select().where({id: tokenDecod.id})
    const arrTotalArrecadado = await db("historicossalvos").sum("precoReal").where({id_profissional: tokenDecod.id})
    if(arrTotalArrecadado.length > 0){
      arrInfosAtendente[0].totalArrecadado = arrTotalArrecadado[0]["sum(`precoReal`)"]
    }else{
      arrInfosAtendente[0].totalArrecadado = 0
    }

    return res.json({codigo: 200, detalhes: "sucesso", res: arrInfosAtendente[0]})
  }catch(err){
    return res.json({codigo: 500, detalhes: "ocorreu um erro ao pegar os valores do banco de dados"})
  }

})


server.post("/criarSala", async (req: Request, res: Response) => { 

  const {idCliente, idProfissional, precoConsultaVar, tempoConsultaVar} = req.body
  console.log("TEMPO CON SULTA VAR")
  console.log(tempoConsultaVar)

  try{

    await db("salas").insert({id_cliente: idCliente, id_profissional: idProfissional, historico: "", precoConsulta: precoConsultaVar, tempoConsulta: tempoConsultaVar})
    const arrTempoAtual = await db("salas").select("inicioConsulta").where({id_cliente: idCliente, id_profissional: idProfissional})
    await db("salas").update({finalConsulta: db.raw('date_add(?, INTERVAL ? minute)', [arrTempoAtual[0].inicioConsulta, tempoConsultaVar])}).where({id_cliente: idCliente}).andWhere({aberta: true});

    const arrIdSala = await db("salas").select("idSala").where({id_cliente: idCliente}).andWhere({aberta: true})
    io.sockets.emit("novaSala", {newRoom: arrIdSala[0].idSala, createdById: idCliente, idProfissional}) //É um problema enviar esse nova sala para todos os sockets
    await db("profissionais").update({status: "ocupado"}).where({id: idProfissional})
    console.log("ta acionando o emi mudStatus")
    io.sockets.emit("mudStatus", {status: "ocupado", id: idProfissional.toString()})
    console.log("ja acionouuu")
    res.json({codigo: 200, detalhes: "sucesso", res: arrIdSala[0].idSala})
  }catch(err){
    res.json({codigo: 500, detalhes: "ocorreu um erro ao inserir um dado ao banco de dados"})

  }

})


server.get("/buscarSalasAtendente", confereTokenAtendente, async (req: Request, res: Response) => {


  const tokenDecod = tokenAtendenteDecodificado(req, res)


  if(tokenDecod.id == 0){
    return res.json(["erro", "ocorreu algum erro ao verificar o token"])
  }

  let arrConversas = []

  try{
    arrConversas = await db("salas").select("idSala", "id_cliente", "tempoConsulta", "precoConsulta", "finalConsulta").where({id_profissional: tokenDecod.id}).andWhere({aberta: true})
    console.log("id q chegou do profissional é: " + tokenDecod.id)
    if(arrConversas.length > 0){
      for(let i = 0; i < arrConversas.length; i++){
        const idClienteAtual = arrConversas[i].id_cliente
        const arrNomeAtual = await db("usuarios").select("nome", "saldo", "dataNas").where({id: idClienteAtual})
        const arrPrecoTempoAtual = await db("salas").select("tempoConsulta", "precoConsulta", "finalConsulta", "minutosPassados").where({id_cliente: idClienteAtual})
  
        if(arrNomeAtual.length > 0 && arrPrecoTempoAtual.length > 0){
          arrConversas[i].nome = arrNomeAtual[0].nome
          arrConversas[i].dataNas = arrNomeAtual[0].dataNas
          arrConversas[i].precoConsulta = arrPrecoTempoAtual[0].precoConsulta
          arrConversas[i].tempoConsulta = arrPrecoTempoAtual[0].tempoConsulta
          arrConversas[i].finalConsulta = arrPrecoTempoAtual[0].finalConsulta
          arrConversas[i].saldo = arrNomeAtual[0].saldo
          arrConversas[i].minutosPassados = arrPrecoTempoAtual[0].minutosPassados
        }else{
          arrConversas[i].nome = "Usuário"
          arrConversas[i].precoConsulta = 0
          arrConversas[i].tempoConsulta = 0
          arrConversas[i].finalConsulta = new Date()
          arrConversas[i].minutosPassados = 0
        }
  
      }
    }

    console.log(arrConversas)
  }catch(err){
    return res.json({codigo: 500, detalhes: "ocorreu um erro ao buscar os dados no banco de dados"})
  }

  return res.json(
    {codigo: 200, detalhes: "sucesso", res: arrConversas})

})


server.get("/SetarOffline", confereTokenAtendente, async (req: Request, res: Response) => {
  const tokenDecod = tokenAtendenteDecodificado(req, res)

  if(tokenDecod.id == 0){
    return res.json({codigo: 500, detalhes: "ocorreu algum erro ao verificar o token"})
  }

  try{
    await db("profissionais").update({status: "offline"}).where({id: tokenDecod.id})
    io.sockets.emit("mudStatus", {status: "offline", id: tokenDecod.id})
    res.json({codigo: 200, detalhes: "status: offline"})
  }catch(err){
    return res.json({codigo: 500, detalhes: "erro ao setar status do atendente. Por favor, tente novamente"})
  }

})


server.post("/pegarInfoCliente", confereTokenAtendente, async (req: Request, res: Response) => {
  const tokenDecod = tokenAtendenteDecodificado(req, res)
  const {idCliente} = req.body

  try{
    let arrInfoCliente = await db("usuarios").select("nome", "email", "saldo", "dataNas").where({id: Number(idCliente)})
    for(let i = 0; i < arrInfoCliente.length; i++){
      const arrPrecoTempo = await db("salas").select("precoConsulta", "tempoConsulta", "finalConsulta", "minutosPassados").where({id_cliente: idCliente, id_profissional: tokenDecod.id})
      if(arrPrecoTempo){
        if(arrPrecoTempo[0]){
          arrInfoCliente[i].tempoConsulta = arrPrecoTempo[0].tempoConsulta
          arrInfoCliente[i].precoConsulta = arrPrecoTempo[0].precoConsulta
          arrInfoCliente[i].finalConsulta = arrPrecoTempo[0].finalConsulta
          arrInfoCliente[i].minutosPassados = arrPrecoTempo[0].minutosPassados
        }else{
          arrInfoCliente[i].tempoConsulta = 0
          arrInfoCliente[i].precoConsulta = 0
          arrInfoCliente[i].finalConsulta = new Date()
          arrInfoCliente[i].minutosPassados = 0
        }
      }else{
        arrInfoCliente[i].tempoConsulta = 0
        arrInfoCliente[i].precoConsulta = 0
        arrInfoCliente[i].finalConsulta = new Date()
        arrInfoCliente[i].minutosPassados = 0
      }

    }
    console.log("conseguiu pegar arrInfo")
    return res.json({codigo: 200, detalhes: "sucesso", res: arrInfoCliente[0]})
  }catch(err){
    console.log("NAAAAO conseguiu pegar arrInfo")
    return res.json({codigo: 500, detalhes: "erro", res: {nome: "Usuário", email: ""}})
  }
})

server.get("/infoMeuAtendente", confereTokenUsuario, async (req: Request, res: Response) => {
  const tokenDecod = tokenUsuarioDecodificado(req, res)

  if(tokenDecod.id == 0){
    return res.json(["erro", "ocorreu algum erro ao verificar o token"])
  }

  try{
    const arrIdMeuProfissional = await db("salas").select("id_profissional").where({id_cliente: tokenDecod.id}) 
    if(arrIdMeuProfissional.length > 0){
      const arrInfosMeuAtendente = await db("profissionais").select().where({id: arrIdMeuProfissional[0].id_profissional})
      if(arrInfosMeuAtendente.length > 0){
        arrInfosMeuAtendente[0].totalArrecadado = 0
        return res.json({codigo: 200, detalhes: "sucesso", res: arrInfosMeuAtendente[0]})
      }else{
        return res.json({codigo: 500, detalhes: "ocorreu algum erro, por favor, tentar novamente" })
      }
    }else{
      return res.json({codigo: 500, detalhes: "ocorreu algum erro, por favor, tentar novamente" })
    }
  }catch(err){
    return res.json({codigo: 500, detalhes: "ocorreu algum erro, por favor, tentar novamente" })
  }

})
  


httpServer.listen(8080)