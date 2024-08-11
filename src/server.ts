import express, {NextFunction, Request, Response} from "express"
import knex from "knex"
import dotenv from "dotenv"
import bcrypt from "bcryptjs"
import jwt, { JwtPayload } from "jsonwebtoken"
import cors from "cors"
import multer from "multer"
import path from "path"

dotenv.config()

const server = express()
server.use(cors())
server.use(express.json())

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

      next()

  }catch(err){
      return res.json({codigo: 500, detalhes: "erro ao verificar o token jwt"})
  }
}


function confereTokenUsuario(req: Request, res: Response, next: NextFunction){    
  const auth = req.headers['authorization']

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

server.get("/confereTokenAtendente", confereTokenAtendente, (req: Request, res: Response) => {
  res.json({codigo: 200, detalhes: "acesso liberado"})
})

server.get("/confereTokenUsuario", confereTokenUsuario, (req: Request, res: Response) => {
  res.json({codigo: 200, detalhes: "acesso liberado"})
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
  


server.listen(8080)