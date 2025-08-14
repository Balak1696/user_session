const Joi = require('joi');

const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
//register
const signupSchema = Joi.object({
  firstname: Joi.string()
    .pattern(/^[A-Za-z\s]+$/)
    .min(3)
    .max(50)
    .required()
    .messages({
      'string.pattern.base': `"First name" can only contain letters and spaces`,
      'string.empty': `"First name" cannot be empty`,
      'string.min': `"First name" should have at least {#limit} characters`,
      'string.max': `"First name" should have at most {#limit} characters`,
      'any.required': `"First name" is required`,
    }),
  lastname: Joi.string()
    .pattern(/^[A-Za-z\s]+$/)
    .min(1)
    .max(50)
    .required()
    .messages({
      'string.pattern.base': `"Last name" can only contain letters and spaces`,
      'string.empty': `"Last name" cannot be empty`,
      'string.min': `"Last name" should have at least {#limit} characters`,
      'string.max': `"Last name" should have at most {#limit} characters`,
      'any.required': `"Last name" is required`,
    }),
  email: Joi.string()
    .email()
    .pattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)
    .required()
    .messages({
      'string.email': `"Email" must be a valid email address`,
      'string.empty': `"Email" cannot be empty`,
      'any.required': `"Email" is required`,
    }),
  password: Joi.string()
    .min(8)
    .required()
    .messages({
      'string.min': `"Password" must contain at least {#limit} characters`,
      'string.empty': `"Password" cannot be empty`,
      'any.required': `"Password" is required`,
    }),
  terms: Joi.boolean().valid(true).required().messages({
    'any.only': `"Terms" must be accepted`,
    'any.required': `"Terms" is required`,
  }),
});

//login
const loginSchema = Joi.object({
  email: Joi.string().pattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/,).required().messages({
    'string.empty': 'Email is required',
    'string.email': 'Please provide a valid email address',
    'any.required': 'Email is required',
  }),
  password: Joi.string()
    .required()
    .messages({
      'string.empty': 'Password is required',
      'any.required': 'Password is required',
    }),
});

//verifyotp
const verifyotpSchema = Joi.object({
  email: Joi.string()
  .email()
  .pattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)
  .required()
  .messages({
    'string.email': `"Email" must be a valid email address`,
    'string.empty': `"Email" cannot be empty`,
    'any.required': `"Email" is required`,
  }),
  otp: Joi.string()
  .required()
  .messages({
    'string.empty': `"OTP" cannot be empty`,
    'any.required': `"OTP" is required`,
  })
});

//resendOtp
const resendOtpSchema = Joi.object({
  email: Joi.string()
  .email()
  .pattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)
  .required()
  .messages({
    'string.email': `"Email" must be a valid email address`,
    'string.empty': `"Email" cannot be empty`,
    'any.required': `"Email" is required`,
  })
});
//forgetpassword
const forgotPasswordSchema = Joi.object({
  email: Joi.string().pattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/,).required().messages({
    'string.empty': 'Email is required',
    'string.email': 'Please provide a valid email',
  }),
});
//resetPassword
const resetPasswordSchema = Joi.object({
  token: Joi.string().required().messages({
    'string.empty': 'Token is required',
    'string.base': 'Token must be a valid string',
  }),
  newPassword: Joi.string().pattern(passwordRegex).required().messages({
    'string.empty': 'Password is required',
      'string.pattern.base': 'Password must be at least 8 characters long, include uppercase, lowercase, number, and special character',
      'any.required': 'Password is required',
  }),
});

//changePassword
const changePasswordSchema = Joi.object({
  oldPassword: Joi.string().pattern(passwordRegex).required().messages({
    'string.empty': 'Please oldPassword is required',
    'string.pattern.base': 'Password must be at least 8 characters long, include uppercase, lowercase, number, and special character',
    'any.required': 'Password is required',
  }),
  newPassword: Joi.string().pattern(passwordRegex).required().messages({
    'string.empty': 'Please New Password is required',
    'string.pattern.base': 'Password must be at least 8 characters long, include uppercase, lowercase, number, and special character',
    'any.required': 'Password is required',
  }),
});
const validate = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({ errors: error.details.map((err) => err.message) });
  }
  next();
};
const validateQuery = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.query, { abortEarly: false });
  if (error) {
    return res.status(400).json({ errors: error.details.map((err) => err.message) });
  }
  next();
};

  
  const validateParams= (schema) => (req, res, next) => {
    const { error } = schema.validate(req.params, { abortEarly: false });
    if (error) {
      return res.status(400).json({ errors: error.details.map((err) => err.message) });
    }
    next();
  };
  

  module.exports={
    signupSchemaValidator:validate(signupSchema),
    loginSchemaValidator:validate(loginSchema),
    verifyotpSchemaValidator:validate(verifyotpSchema),
    resendOtpSchemaValidator:validate(resendOtpSchema),
    forgotPasswordSchemaValidator:validate(forgotPasswordSchema),
    resetPasswordSchemaValidator:validate(resetPasswordSchema),
    changePasswordSchemaValidator:validate(changePasswordSchema),

    
  }