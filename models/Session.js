const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Session = sequelize.define('Session', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  userId: { type: DataTypes.INTEGER, allowNull: false },
  token: { type: DataTypes.STRING, allowNull: false },
  ipAddress: { type: DataTypes.STRING, allowNull: true },
  deviceInfo: { type: DataTypes.STRING, allowNull: true },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false,
  },
}, {
  timestamps: true
});

Session.associate = (models) => {
  Session.belongsTo(models.User, { foreignKey: 'userId' });
};

module.exports = Session;
