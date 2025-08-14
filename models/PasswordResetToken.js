// models/PasswordResetToken.js
const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const PasswordResetToken = sequelize.define('PasswordResetToken', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  userId: { type: DataTypes.INTEGER, allowNull: false },
  token: { type: DataTypes.STRING, allowNull: false },
  expiresAt: { type: DataTypes.DATE, allowNull: false },
  ipAddress: { type: DataTypes.STRING, allowNull: true },
  //deviceInfo: { type: DataTypes.STRING, allowNull: true },
  used: { type: DataTypes.BOOLEAN, defaultValue: false }
});

PasswordResetToken.associate = (models) => {
  PasswordResetToken.belongsTo(models.User, { foreignKey: 'userId' });
};

module.exports = PasswordResetToken;
