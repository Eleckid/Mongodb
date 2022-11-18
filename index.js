const argon2 = require("argon2");
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const { User } = require("./model/user");
var jwt = require('jsonwebtoken');
const  checkJwt  = require("./middlewares/checkjwt");

app.use(
  express.urlencoded({
    extended: true,
  })
);
app.use(express.json());

const start = async () => {
  try {
    mongoose
      .connect("mongodb://0.0.0.0:27017/test")
      .catch((err) => console.log(err.reason));
    app.listen(3000, () => console.log("Server started on port 3000"));
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
};

start();

// Verification des identifiants

app.post("/api/auth/register", async (req, res) => {
  const body = req.body;
  if (body.nom.length <= 1) {
    return res.status(401).json({
      error: true,
      message: "Veuillez saisir votre nom"
    })
  }
  if (body.prenom.length <= 1) {
    return res.status(401).json({
      error: true,
      message: "Veuillez saisir votre prenom"
    })
  }
  if (body.telephone.length <= 1) {
    return res.status(401).json({
      error: true,
      message: "Veuillez saisir votre numéro !"
    })
  }
  if (body.email.length <= 1) {
    return res.status(401).json({
      error: true,
      message: "Veuillez saisir votre adresse e-mail"
    })
  }

  if (body.password !== body.password2) {
    return res.status(401).json({
      error: true,
      message: "Mot de passe non identique !"
    })
  }
  if (body.password.length <= 4) {
    return res.status(401).json({
      error: true,
      message: "Votre mot de passe doit posseder plus de 4 caractères ! "
    })
  }
  
  const hash = await argon2.hash(body.password);


  const user = new User({
    nom: body.nom,
    prenom: body.prenom,
    email: body.email,
    telephone: body.telephone,
    password: hash
  })

  user.save()

  return res.status(201).json({
    user : {
      nom : user.nom,
      prenom : user.prenom,
      telephone : user.telephone,
      email : user.email
   },
    message : "Utilisateur créé avec succès !"
  })

})

app.post("/api/auth/login", async (req, res) => {
    const body = req.body;
    if (body.email.length <= 1) {
      return res.status(401).json({
        message: "Veuillez entrer votre adresse e-mail !"
      })
    }
    if (body.password.length <= 4) {
      return res.status(401).json({
        message: "Votre mot de passe doit posseder plus de 4 caractères !"
      })
    }

    const user = await User.findOne({
        email : body.email
    })

    if(!user){
      return res.status(401).json({
          message : "Utilisateur Introuvable ! Veuillez d'abord vous inscrire !"
      })
    }
    const password = await argon2.verify(user.password, body.password);
    if (!password){
        return res.status(401).json({
          message : "mot de passe incorrecte :!"
        })
    }
      //user.password = undefined;

    const token = jwt.sign({
        id : user._id,
        email : body.email
    },'secret',{
      expiresIn : '1h'
    })
    res.cookie("token", token, {
      httpOnly: true,
    })

    res.status(200).json({
      user : {
         email : user.email,
         nom : user.nom,
         prenom : user.prenom,
         telephone : user.telephone
      },
      message : "Connexion réussie ! "
    })
    
})

app.get("/api/user/profile",checkJwt,async(req,res)=>{
     const user = await User.findOne({
        email : res.locals.jwtPayload.email,
    }) 
    // Si le mail a été supprimé

    if(email == ""){
  
      return res.status(500).json({
        message : "Veuillez d'abord vous connecter ! "
      })
    }
    res.status(200).json({
      user : {
         nom : user.nom,
         prenom : user.prenom,
         telephone : user.telephone,
         email : user.email
      },
      message : "Profil Trouvé ! "
    })
 })


app.put("/api/user/edit", checkJwt , async (req, res) => {

  const user = await User.findOne({
     email : res.locals.jwtPayload.email 
  }) ;
  user.prenom = req.body.prenom || user.prenom;
  user.nom = req.body.nom || user.nom;
  
  await user.save();
   
  res.status(201).json({
    user : {
       email : user.email,
       nom : user.nom,
       prenom : user.prenom,
       telephone : user.telephone
    },
    message : "Modification du compte réussie ! "
  })
   
  })
  app.put("/api/user/edit-password", checkJwt , async (req, res) => {
    const user = await User.findOne({
       email : res.locals.jwtPayload.email 
    }) ;

    if (req.body.password !== req.body.password2) {
      return res.status(401).json({
        error: true,
        message: "Le mot de passe ne correspond pas !"
      })
    }
    
    const hash = await argon2.hash(req.body.password);
    user.password = hash;
    await user.save();

     
    res.status(201).json({
      message : "Le mot de passe a bien été modifié ! "
    })
     
    })
  
    app.put("/api/user/edit-telephone", checkJwt , async (req, res) => {

      const user = await User.findOne({
         email : res.locals.jwtPayload.email 
      }) ;
      user.telephone = req.body.telephone || user.telephone;
      
      await user.save();
       
      res.status(201).json({
      
        message : "Le numéro de telephone a bien été modifié ! "
      })
       
      })
    
      app.put("/api/user/edit-email", checkJwt , async (req, res) => {
        if( req.body.email == ""){
            return res.status(500).json({
               message : "Veuillez entrer votre adresse e-mail"
            });
        }
        const user = await User.findOne({
           email : res.locals.jwtPayload.email 
        }) ;
        user.email = req.body.email;
        
        await user.save();
         
        res.status(201).json({
        
          message : "L'e-mail a été modifié avec succès ! "
        })
         
        })
 
           
app.delete("/api/user/delete",checkJwt, async (req, res) => {
  await User.findOneAndRemove (res.locals.jwtPayload.email)
  .then(function (user) {
      res.status(200).json({
        message : " Votre profil a été supprimé avec succès ! Un email de confirmation vous a été envoyé "
      });
  })
  .catch(function (error) {
      res.status(500).json(error);
  });
})
