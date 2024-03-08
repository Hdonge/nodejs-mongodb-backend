import jwt from 'jsonwebtoken';

import { asyncHandler } from '../utils/asyncHandler.js';
import ApiError from '../utils/ApiError.js';
import { User } from '../models/user.model.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import ApiResponse from '../utils/ApiResponse.js';


const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    }
    catch (err) {
        throw new ApiError(500, "Something went wrong while generating access and refresh tokens");
    }
}

const registerUser = asyncHandler(async (req, res) => {
    //get user details from client
    //validation - not empty
    // check if user already exists , username, email
    // check images & avatar
    //upload them to cloudinary, avatar
    //create user object - create entry in db
    //remove password and refresh token from response
    // check for user creation
    //retrun res

    const { username, password, email, fullname } = req.body;
    console.log(username, password, email, fullname);

    if ([fullname, email, username, password].some(f => f === undefined || f?.trim() === "")) {
        throw new ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    });

    if (existedUser) throw new ApiError(409, "User with email or username already exists");

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage && Array.isArray(req.files?.coverImage) ? req.files?.coverImage[0]?.path : null;

    if (!avatarLocalPath) throw new ApiError(400, "Avatar file is required");

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) throw new ApiError(400, "Avatar file is required");

    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    });

    const createdUser = await User.findOne(user._id).select("-password -refreshToken");

    console.log(createdUser);

    if (!createdUser) throw new ApiError(500, "Something went wrong while creating user");

    return res.status(201).json(new ApiResponse(200, createdUser, "User registered successfully"));

});

const login = asyncHandler(async (req, res) => {
    //req body -> data
    //username or email
    //find the user
    //password check
    //access or refresh token
    //send cookie


    const { email, username, password } = req.body;
    if (!username && !email) throw new ApiError(400, "username or password is required");

    const user = await User.findOne({
        $or: [{ username }, { email }]
    });

    if (!user) throw new ApiError(404, "User does not exist");

    const isPasswordCorrect = await user.isPasswordCorrect(password);

    if (!isPasswordCorrect) throw new ApiError(401, "Invalid user credentials");

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    const loginCookieOptions = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
        .cookie("accessToken", accessToken, loginCookieOptions)
        .cookie("refreshToken", refreshToken, loginCookieOptions)
        .json(new ApiResponse(200,{
            user: loggedInUser,
            accessToken, // this is may be useful for the client which cant set cookies
            refreshToken // this is may be useful for the client which cant set cookies
        }, "user is logged in!"))

});

const logout = asyncHandler(async (req, res) => {
    // reset refresh token from user
    // clear cookie
    // send logout response

    const { _id } = req.user;

    await User.findByIdAndUpdate(
        _id,
        {
            $unset: {
                refreshToken: 1 // this removes the field from document
            }
        },
        {
            new: true
        }
    );

    const loginCookieOptions = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
        .clearCookie("accessToken", loginCookieOptions)
        .clearCookie("refreshToken", loginCookieOptions)
        .json(new ApiResponse(200, "User is logged out"));

});

const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

        if (!incomingRefreshToken) throw new ApiError(401, "Unauthorized request");

        const decodedToken = await jwt.verify(incomingRefreshToken, REFRESH_TOKEN_SECRET);

        const user = User.findById(decodedToken?._id);

        if (!user) throw new ApiError(401, "Invalid refresh token");

        if (incomingRefreshToken !== user.refreshToken) {
            throw new ApiError(401, "Refreshtoken is expired or used.");
        }

        const { accessToken, refreshToken: newRefreshToken } = await generateAccessAndRefreshTokens(user._id);

        const loginCookieOptions = {
            httpOnly: true,
            secure: true
        }

        return res.status(200)
            .cookie("accessToken", accessToken, loginCookieOptions)
            .cookie("refreshToken", newRefreshToken, loginCookieOptions)
            .json(new ApiResponse(200, { accessToken, refreshToken: newRefreshToken }, "Access token refreshed"));

    }
    catch (err) {
        throw new ApiError(401, err.message || "invalid refresh token");
    }
});

const chamgeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const { _id } = req.user;

    const user = await User.findById(_id);
    const isPasswordCorrect = user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) throw new ApiError(400, 'Invalid old password');

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res.status(200).json(new ApiResponse(200, "Password changed successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(new ApiResponse(200, req.user, "Current user is fetched successfully"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
    const { fullName, email } = req.body

    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email: email
            }
        },
        { new: true }

    ).select("-password")

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Account details updated successfully"))
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if (!avatar.url) {
        throw new ApiError(400, "Error while uploading on avatar")

    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        { new: true }
    ).select("-password")

    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "Avatar image updated successfully")
        )
})

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover image file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!coverImage.url) {
        throw new ApiError(400, "Error while uploading on avatar")

    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        { new: true }
    ).select("-password")

    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "Cover image updated successfully")
        )
})

export {
    registerUser,
    login,
    logout,
    refreshAccessToken,
    chamgeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
}
