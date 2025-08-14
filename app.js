const express = require('express');
const dotenv = require('dotenv');
const morgan = require('morgan');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const helmet = require('helmet');
const { apiLimiter } = require('./middlewares/rateLimit');

const authRoutes = require('./routes/authRoutes');

dotenv.config();


const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); 
app.use(
  session({
    secret:process.env.SESSION_SECRET || 'defaultSecret', 
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, 
      secure: true,
      sameSite: 'Strict', 
      maxAge: 1000 * 60 * 60 * 24, 
    },
  })
);
app.use(morgan('tiny'));  
app.use(helmet());  

const corsOptions = {
  origin : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE','PATCH'],
  credentials: true, 
};
app.use(cors(corsOptions));

app.use('/api/', apiLimiter);  
app.use('/api/auth', authRoutes);

app.get('/', (req, res) => {
  res.send('Welcome to the API successfully');
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, async () => {
  try {
    const sequelize = require('./config/database');
    await sequelize.authenticate();
  } catch (error) {
    console.error('Error connecting to the database:', error);
  }
});

module.exports=app
