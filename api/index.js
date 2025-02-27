const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors")
const app = express();

app.use(cors({
  origin: "*",
  credentials: true,
}));

app.use(express.json());

const users = [
  {
    id: "1",
    username: "john",
    password: "John0908",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "Jane0908",
    isAdmin: false,
  },
  {
    id: "3",
    username: "JohnDoe",
    password: "12345",
    isAdmin: false,
  },
];

let refreshTokens = [];
  
app.post("/api/refresh", (req, res) => {
  const refreshToken = req.body.token;

  if (!refreshToken) {
    return res.status(401).json("You are not validated!");
  } 

  if(!refreshTokens.includes(refreshToken)){
    return res.status(403).json("JSON Refresh token is not valid")
  }  

  jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
    err && console.log(err)
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken)

    const newAccessToken = generateAccessToken(user)
    const newRefreshToken = generateRefreshToken(user)

    refreshTokens.push(newRefreshToken)
    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    })
  })
});

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
    expiresIn: "30s",
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshSecretKey");
};

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken)
    res.status(200).json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
      users
    });
  } else {
    res.status(400).json("Username or password incorrect!");
  }
});



const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid");
      }

      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated!");
  }
};

app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted!");
  } else {
    res.status(403).json("You can not delete this user!");
  }
});

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken)
  res.status(200).json("Logged Out Successfully!")
})

app.listen(5000, () => {
  console.log("Backend server is running!");
});
