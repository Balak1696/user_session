const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const User = sequelize.define('User', {
  id: {type: DataTypes.INTEGER,primaryKey: true,autoIncrement: true},
  firstname: { type: DataTypes.STRING, allowNull: false },
  lastname: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING,allowNull: false },
  password: { type: DataTypes.STRING, allowNull: false },
  isVerified: { type: DataTypes.BOOLEAN, defaultValue: false }, 
  isActive: { type: DataTypes.BOOLEAN,defaultValue: false},
  otp: { type: DataTypes.STRING, allowNull: true },
  otpExpiresAt: { type: DataTypes.DATE, allowNull: true },
  last_LoggedIn: { type: DataTypes.DATE, allowNull: true},
  terms: { type: DataTypes.BOOLEAN, allowNull: false ,defaultValue:false}, 
});

User.associate = (models) => { 
  User.hasMany(models.PasswordResetToken, { foreignKey: 'userId' });
};

module.exports = User;
