const sequelize = require('../config/database');
const User = require('./User');
const PasswordResetToken = require('./PasswordResetToken');
const Session = require('./Session');

const models = {
  User,PasswordResetToken,Session
  };
Object.keys(models).forEach((modelName) => {
  if (models[modelName].associate) {
    models[modelName].associate(models);
  }
});


sequelize
  .sync({ alter: true })
  .then(() => {
    console.log('Database synced successfully');
  })
  .catch((error) => {
    console.error('Error syncing the database:', error);
  });

module.exports = models;
