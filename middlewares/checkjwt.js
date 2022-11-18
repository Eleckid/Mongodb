const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    const token = req.headers.cookie.replace("token=","");
  let jwtPayload;
  
  try {
    jwtPayload = jwt.verify(token, 'secret');
    res.locals.jwtPayload = jwtPayload;
  } catch (error) {
    res.status(401).send({ error: "unauthorized" });
    return;
  }
  const { id, email } = jwtPayload;
  const newToken = jwt.sign({ id, email },'secret', {
    expiresIn: "1h",
  });
  res.setHeader("token", newToken);
  next();
};