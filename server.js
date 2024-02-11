import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import Jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import { config as dotenvConfig } from "dotenv";

//env variables
dotenvConfig();
const envUserName = process.env.MONGODB_USERNAME;
const envPassWord = process.env.MONGODB_PASSWORD;

const jwtKey = "jwt-key";

const app = express();
app.use(cors());
app.use(bodyParser.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
});
app.use(limiter);

const port = 5000;

mongoose
  .connect(
    `mongodb+srv://${envUserName}:${envPassWord}@mainnikedb.jx4pwkk.mongodb.net/brainop`
  )
  .then(() => console.log("mongodb connected"))
  .catch((error) => {
    console.log("mongodb error: ", error);
  });

const signupSchema = new mongoose.Schema({
  upName: {
    type: String,
    required: true,
  },
  upEmail: {
    type: String,
    required: true,
    unique: true,
  },
  upPassword: {
    type: String,
    required: true,
  },
});

const signUpModel = mongoose.model("signup", signupSchema);

app.get("/", (req, res) => {
  res.send("<h1>welcome!</h1>");
});

app.post("/signup", async (req, res) => {
  const { sendName, sendEmail, sendPassword } = req.body;
  try {
    const existingUser = await signUpModel.findOne({ upEmail: sendEmail });
    if (existingUser) {
      res.status(200).json({ userExist: "exist" });
    } else {
      const hashPassword = await bcrypt.hash(sendPassword, 10);
      const newUser = await signUpModel.create({
        upName: sendName,
        upEmail: sendEmail,
        upPassword: hashPassword,
      });

      Jwt.sign(
        { userId: newUser._id, userEmail: newUser.upEmail },
        jwtKey,
        { expiresIn: "2h" },
        (err, token) => {
          if (err) {
            res.status(500).json({ result: "something went wrong with jwt" });
          } else {
            console.log("user sign up", newUser);
            res
              .status(200)
              .json({ user: newUser, auth: token, signup: "signup" });
          }
        }
      );
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error from signup" });
  }
});

app.listen(port, () => {
  console.log(`server listening on port ${port}`);
});
