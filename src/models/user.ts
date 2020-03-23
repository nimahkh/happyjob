import mongoose from 'mongoose';
import bcrypt from 'bcrypt-nodejs';
import crypto from 'crypto';

export type UserDocument = mongoose.Document & {
    email: string;
    password: string;
    name: string;
    passwordResetToken: string;
    passwordResetExpires: Date;
    facebook: string;
    profile: {
        name: string;
        gender: string;
        location: string;
        website: string;
        picture: string;
    };

    comparePassword: comparePasswordFunction;
    gravatar: (size: number) => string;
};

type comparePasswordFunction = (candidatePassword: string, cb: (err: any, isMatch: any) => {}) => void;

/**
 * User Schema
 */
const userSchema = new mongoose.Schema(
    {
        _id: mongoose.Schema.Types.ObjectId,
        email: {
            type: String,
            required: true
        },
        name: {
            type: String,
            required: true
        },
        password: {
            type: String
        }
    },
    {
        timestamps: true
    }
);

/**
 * Password hash middleware.
 */
userSchema.pre('save', function save(this: any, next) {
    const user = this as UserDocument;
    if (!user.isModified('password')) { return next(); }
    bcrypt.genSalt(10, (err, salt) => {
        if (err) { return next(err); }
        // tslint:disable-next-line:no-shadowed-variable
        bcrypt.hash(user.password, salt, undefined, (err: mongoose.Error, hash) => {
            if (err) { return next(err); }
            user.password = hash;
            next();
        });
    });
});

const comparePassword: comparePasswordFunction =  (candidatePassword, cb)=> {
    // @ts-ignore
    bcrypt.compare(candidatePassword, this.password, (err: mongoose.Error, isMatch: boolean) => {
        cb(err, isMatch);
    });
};

userSchema.methods.comparePassword = comparePassword;

/**
 * Helper method for getting user's gravatar.
 */
userSchema.methods.gravatar = function (size: number = 200) {
    if (!this.email) {
        return `https://gravatar.com/avatar/?s=${size}&d=retro`;
    }
    const md5 = crypto.createHash('md5').update(this.email).digest('hex');
    return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
};

/**
 * Statics
 */
userSchema.statics = {
    /**
     * Get User
     * @param {ObjectId} id - The objectId of user.
     */
    get(id: string): mongoose.Document {
        return this.findById(id)
            .execAsync()
            .then((user: any) => {
                if (user) {
                    return user;
                }
            });
    }
};

export default mongoose.model('User', userSchema);