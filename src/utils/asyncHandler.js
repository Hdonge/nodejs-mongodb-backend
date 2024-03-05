const asyncHanlder = () => {
    (req, res, next) => {
        Promise.resolve(requestHandler(req, res, next))
            .catch((err) => next(err));
    }
}

export { asyncHanlder };

// const asyncHanlder = (fn) => async (req, res, next) => {
//     try {

//     } catch (err) {
//         res.status(err.code || 500).json({
//             success: false,
//             message: err.message
//         });
//     }
// };
