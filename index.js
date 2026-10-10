import express from "express";
import bodyParser from "body-parser";
import pg from 'pg';
import bcrypt from "bcrypt";
import session from  'express-session';
import passport  from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();


const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie:{
      maxAge: 1000 * 60 * 60*24
    }
  }),
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res ) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});


app.get("/register", (req, res) => {
  res.render("register.ejs");
});


app.get("/secrets",(req,res) => {
  console.log(req.user);
  if(req.isAuthenticated()){
    res.render("secrets.ejs")
  }else {
    res.redirect("/login" )
  }
})


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      // password hashing
      bcrypt.hash(password,saltRounds, async (err,hash) => {
   if (err){
    console.log("Error hashing password:",err);
   } else {  
    console.log("Hashed Password:",hash)
        const result = await db.query(
          // "INSERT INTO users (email, password) VALUES ($1, $2)",
          "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
          [email, hash],
        );
      //console.log(result);
      //res.render("secrets.ejs");
      // session for results
      const user = result.rows[0];
      req.login(user,(err) => {
        console.log(err);
        res.redirect("/secrets");
      })
    }
      })
    }
  } catch (err) {
    console.log(err);
  }
});


app.post("/login",// async (req, res) => {
  // const email = req.body.username;
  // const loginPassword = req.body.password;

  // try {
  //   const result = await db.query("SELECT * FROM users WHERE email = $1", [
  //     email,
  //   ]);
  //   if (result.rows.length > 0) {
  //     //console.log(result.rows);
  //     const user = result.rows[0];
  //     const storedHashedPassword = user.password;

  //     bcrypt.compare(loginPassword,storedHashedPassword,(err,result) =>{
  //       if(err){
  //         console.log("Error comparing password",err)
  //       } else {
  //         if (result) {
  //           res.render("secrets.ejs");
  //         } else {
  //           res.send("Incorrect Password");
  //         }
  //       }
  //     });
      
  //   } else {
  //     res.send("User not found");
  //   }
  // } catch (err) {
  //   console.log(err);
  // }
//}
passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
})
);

// here cb from verify(username,passowrd) is callback function
passport.use(new Strategy( async function verify(username,password,cb){

    try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,// comes from the form
    ]);
    if (result.rows.length > 0) {
      //console.log(result.rows);
      const user = result.rows[0]; //current user from db
      const storedHashedPassword = user.password; ///current user hased password

      bcrypt.compare(password,storedHashedPassword,(err,result) =>{
        if(err){
          //console.log("Error comparing password",err)
       return cb(err);
        } else {
          if (result) {
            //res.render("secrets.ejs");
            return cb(null,user)
          } else {
            //res.send("Incorrect Password");
            return cb(null,false)
          }
        }
      });
      
    } else {
     // res.send("User not found");
           return cb("User not found");

    }
  } catch (err) {
    return cb(err);
  }
}))

passport.serializeUser( (user,cb)=> {
cb(null,user);
});

passport.deserializeUser((user,cb) => {
  cb(null,user);
})


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
