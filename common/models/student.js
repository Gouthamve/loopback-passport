module.exports = function(student) {
	student.afterRemote('**', function(ctx, user, next) {
  console.log("LOL")
  next();
});
};
