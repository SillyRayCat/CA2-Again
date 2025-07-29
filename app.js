// Test :D


// Import required modules
const express = require('express');
const mysql = require('mysql2');
const session = require('express-session'); // set up session management
const multer = require('multer');  // set up multer for file uploads
const flash = require('connect-flash');
const path = require('path');
const fs = require('fs');

const uploadDir = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

// Create an Express application
const app = express();

//set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => 
    cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}${path.extname(file.originalname)}`)
});

const upload = multer({ storage: storage });


//Created mysql connection
const connection = mysql.createConnection({
    host: 'c237-e65p.mysql.database.azure.com',
    port: 3306,
    user: 'c237user',
    password: 'c2372025!',
    database: 'c237_24009380'
  });
const pool = connection.promise(); 
// Connect to the MySQL database
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL database');
});
 
// Set EJS as the view engine
app.set('view engine', 'ejs');

//******** TODO: Create a Middleware to check if user is logged in. ********//
const checkAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    } else {
        req.flash('error', 'You must be logged in to view this resource.');
        res.redirect('/login');
    }
};

//******** TODO: Create a Middleware to check if user is admin. ********//
const checkAdmin = (req, res, next) => {
    if (req.session.user.role === 'admin') {
        return next();
    } else {
        req.flash('error', 'Access denied.');
        res.redirect('/');
    }
};



// Middleware to parse request bodies
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // Serve static files from the 'public' directory

// Middleware for session management
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } // Set to true if using HTTPS
}));

app.use(flash()); // Use flash messages for notifications   

// TO DO:Create a middleware function validate user authentication
const validateRegistration = (req, res, next) => {
    const { username, password, phone_number, email_address, nric,age, gender } = req.body;
    if (!username || !password || !phone_number || !email_address || !nric || ! age || ! gender) {
        return res.status(400).send('All fields are required');
    }

    if (password.length < 6) {
        req.flash('error', 'Password must be at least 6 or more characters long');
        req.flash('formData', req.body);
        return res.redirect('/register');
    }
    next();
};

//******** TODO: Integrate validateRegistration into the register route. ********//
app.post('/register', validateRegistration,(req, res) => {
    //******** TODO: Update register route to include role. ********//
    const { username, password, phone_number, email_address, nric, age, gender,role } = req.body;

    const sql = 'INSERT INTO user (username, password, phone_number, email_address, nric, age, gender, role) VALUES (?, SHA1(?), ?, ?, ?, ?, ?, ?)';
    connection.query(sql, [username, password, phone_number, email_address, nric, age, gender,role], (err, result) => {
        if (err) {
            throw err;
        }
        console.log(result);
        req.flash('success', 'Registration successful! Please log in.');
        res.redirect('/login');
    });
});

app.get('/register', (req, res) => {
    res.render('register', { messages: req.flash('error'), formData: req.flash('formData')[0] });
});

//******** TODO: Insert code for login routes to render login page below ********//
app.get('/login', (req, res) => {
    res.render('login', { 
        messages: req.flash('success'), // Retrieve success messages from session and pass them to the view
        errors: req.flash('error') // Retrieve error messages from session and pass them to the view
    });
});

//******** TODO: Insert code for login routes for form submission below ********//
app.post('/login', (req, res) => {
    const { username,email_address, password } = req.body;

    //Validate username ,email, password
    if (!username|| !email_address || !password) {
        req.flash('error', 'All fields are required.'); 
        return res.redirect('/login');
    }

    const sql = 'SELECT * FROM user WHERE username = ? AND email_address = ? AND password = SHA1(?)';
    connection.query(sql, [username,email_address, password], (err, results) => {
        if (err) {
            throw err;
        }
        if (results.length > 0) {
            // Successful Login
            req.session.user = results[0]; // Store user data in session
            req.flash('success', 'Login successful!');
            //************ TO DO: Update to redirect users to /dashboard route upon successful log in *//
            // res.redirect('/dashboard');
            if (results[0].role === 'admin') {
                res.redirect('/admin'); // Redirect to admin dashboard
            } else {
                res.redirect('/dashboard'); // Redirect to user dashboard
            }
        } else {
            // Invaild credentials
            req.flash('error', 'Invalid username, email or password.');
            return res.redirect('/login');
        }
    });
});



//******** TODO: Insert code for admin route to render dashboard page for admin. ********//
app.get('/admin', checkAuthenticated, checkAdmin, (req, res) => {
  const sql = 'SELECT * FROM user';
  connection.query(sql, (err, users) => {
    if (err) {
      console.error('DB error on /admin:', err);
      return res.status(500).send('Database error');
    }
    res.render('admin', {
      user: req.session.user,     // for your navbar
      users,                      // feeds your Bootstrap table
      messages: req.flash('success')
    });
  });
});

app.get('/dashboard', checkAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin') {
    res.redirect('/admin');
  } else {
    res.render('dashboard', { user: req.session.user, messages: req.flash('success') });
  }

});

// Profile page — load user, their foods, and exercises
app.get('/profile', checkAuthenticated, async (req, res, next) => {
  try {
    // your session user row has a userID field, not “id”
    const user    = req.session.user;
    const userId  = user.userID;

    // pull all foods for this user, newest first
    const [foods] = await pool.query(
      'SELECT * FROM food_tracker WHERE userID = ? ORDER BY foodID DESC',
      [userId]
    );

    // pull all exercises for this user, newest first
    const [exercises] = await pool.query(
      'SELECT * FROM exercise_tracker WHERE userID = ? ORDER BY exerciseID DESC',
      [userId]
    );

    res.render('profile', {
      user,
      foods,
      exercises,
      success: req.flash('success'),
      error:   req.flash('error')
    });
  } catch (err) {
    next(err);
  }
});




app.get('/logout', (req, res) => {
    req.session.destroy(() => {
    res.redirect('/'); // Redirect to login page after logout
    });
});

//******** TODO: Insert code for dashboard route to render dashboard page for users. ********//
app.get('/dashboard', checkAuthenticated, (req, res) => {
    console.log("Logged-in user:", req.session.user);  // ✅ Add this
    res.render('dashboard', { user: req.session.user, messages: req.flash('success') });
});




app.use(flash());
function isLoggedIn(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}



app.get('/', (req, res) => {
    const queries = {
        user: 'SELECT * FROM user',
        exercise_tracker: 'SELECT * FROM exercise_tracker',
        food_tracker: 'SELECT * FROM food_tracker'
    };


    // First query: get user data
    connection.query(queries.user, (err, users) => {
        if (err) return res.status(500).send('Error retrieving users');

        // Second query: get exercise data
        connection.query(queries.exercise_tracker, (err, exercises) => {
            if (err) return res.status(500).send('Error retrieving exercise tracker');

            // Third query: get food data
            connection.query(queries.food_tracker, (err, foods) => {
                if (err) return res.status(500).send('Error retrieving food tracker');

                // Render the page with all data
                res.render('index', {
                    user: users,
                    exercise_tracker: exercises,
                    food_tracker: foods,
                    messages: req.flash('success'),
                    sessionUser: req.session.user
                });
            });
        });
    });
});



app.get('/user/:id', checkAuthenticated, checkAdmin, (req, res) => {
  const userID = req.params.id;
  const sql = 'SELECT * FROM user WHERE userID = ?';
  connection.query(sql, [userID], (err, results) => {
    if (err) {
      console.error('DB error on /user/:id', err);
      return res.status(500).send('Database error');
    }
    if (!results.length) {
      return res.status(404).send('User not found');
    }

    res.render('user', {
      user: req.session.user,        // still your logged-in admin
      selectedUser: results[0],      // the record you clicked
      messages: req.flash('success')
    });
  });
});

app.get('/food_name/:id', (req, res) => {
    //Extract student ID from the request parameters
    const food_name = req.params.id;
    const sql = 'SELECT * FROM food_tracker WHERE food_name = ?';
    // Fetch data from MySQL based on the name
    connection.query(sql, [food_name], (error, results) => {
        if (error) {
            console.error('Database query error:', error.message);
            return res.status(500).send('Error Retrieving food_name by ID');
        }
        if (results.length > 0) {
        // Render the student details page with the fetched data
        res.render('food_name', { name: results[0] });
        }
        else {
            // If no name with the given ID was found, render a 404 page or handle it accordingly
            res.status(404).send('food_name not found');
        }
    });
});

app.get('/exercise_name/:id', (req, res) => {
    //Extract exercise ID from the request parameters
    const exercise_name = req.params.id;
    const sql = 'SELECT * FROM exercise_tracker WHERE exercise_name = ?';
    // Fetch data from MySQL based on the name
    connection.query(sql, [exercise_name], (error, results) => {
        if (error) {
            console.error('Database query error:', error.message);
            return res.status(500).send('Error Retrieving exercise_name by ID');
        }
        if (results.length > 0) {
        // Render the student details page with the fetched data
        res.render('exercise_name', { name: results[0] });
        }
        else {
            // If no name with the given ID was found, render a 404 page or handle it accordingly
            res.status(404).send('exercise_name not found');
        }
    });
});



//add exercise - Jonathan ------------------------------------//
app.get('/addExercise', isLoggedIn, (req, res) => {
  res.render('AddExercise', { message: req.flash('error') });
});

app.post(
  '/addExercise',
  isLoggedIn,
  async (req, res) => {
    const { exercise_name, types, reps, sets } = req.body;

    if (exercise_name.length > 45 || types.length > 45) {
      req.flash('error', 'Field length exceeded.');
      return res.redirect('/addExercise');
    }

    try {
      await pool.query(
        `INSERT INTO exercise_tracker (userID, exercise_name, types, reps, sets)
         VALUES (?,?,?,?,?)`,
        [req.session.user.userID, exercise_name, types, reps, sets]
      );
      req.flash('info', 'Exercise added successfully.');
      res.redirect('/dashboard');
    } catch (err) {
      console.error(err);
      req.flash('error', 'Could not add exercise.');
      res.redirect('/addExercise');
    }
  }
);
//--------------------------------------------------------------//

//add food - Jonathan-------------------------------------------//
app.get('/addFood', isLoggedIn, (req, res) => {
  res.render('AddFood', { message: req.flash('error') });
});

app.post('/addFood', isLoggedIn, upload.single('foodImage'), async (req, res) => {
  const { food_name, carbs, protein, calories, fats } = req.body;

  if (food_name.length > 45) {
    req.flash('error', 'Food name exceeds 45 characters.');
    return res.redirect('/addFood');
  }

  const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

  try {
    await pool.query(
      `INSERT INTO food_tracker (userID, food_name, carbs, protein, calories, fats, image)
       VALUES (?,?,?,?,?,?,?)`,
      [req.session.user.userID, food_name, carbs, protein, calories, fats, imagePath]
    );
    req.flash('info', 'Food added successfully.');
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    req.flash('error', 'Could not add food.');
    res.redirect('/addFood');
  }
});
//---------------------------------------------------------------//

// update exercise -Elden-------------------------------------//
app.get('/updateFood/:id', checkAuthenticated, (req, res) => {
  const foodID = req.params.id;
  const sql = 'SELECT * FROM food_tracker WHERE foodID = ?';  // Fetch food data by ID          
  connection.query(sql, [foodID], (error, results) => {
    if (error) {
      console.error("Error fetching food:", error);
      return res.status(500).send('Error fetching food');
    } else if (results.length === 0) {
      return res.status(404).send('Food not found');
    } else {
      const food = results[0];
      // Only allow if user owns the food or is admin
      if (
        req.session.user.role === 'admin' ||
        food.userID === req.session.user.userID
      ) {
        res.render('updateFood', { food, messages: req.flash('error') });
      } else {
        req.flash('error', 'Unauthorized to update this food entry.');
        return res.redirect('/dashboard');
      }
    }
  });
});

app.post('/updateFood/:id', checkAuthenticated, (req, res) => {
  const foodID = req.params.id;
  const { food_name, carbs, protein, calories, fats } = req.body;

  // First, fetch the food entry to check ownership or admin
  const fetchSql = 'SELECT userID FROM food_tracker WHERE foodID = ?';
  connection.query(fetchSql, [foodID], (fetchErr, results) => {
    if (fetchErr) {
      console.error("Error fetching food for update:", fetchErr);
      return res.status(500).send('Error fetching food');
    }
    if (results.length === 0) {
      return res.status(404).send('Food not found');
    }
    const foodOwnerId = results[0].userID;
    const currentUser = req.session.user;

    // Only allow if current user is owner or admin
    if (currentUser.userID !== foodOwnerId && currentUser.role !== 'admin') {
      req.flash('error', 'Unauthorized to update this food entry.');
      return res.redirect('/dashboard');
    }

    const updateSql = 'UPDATE food_tracker SET food_name = ?, carbs = ?, protein = ?, calories = ?, fats = ? WHERE foodID = ?';
    connection.query(updateSql, [food_name, carbs, protein, calories, fats, foodID], (updateErr) => {
      if (updateErr) {
        console.error("Error updating food:", updateErr);
        return res.status(500).send('Error updating food');
      }
      res.redirect('/dashboard');
    });
  });
});
//---------------------------------------------------------------//

//View All Items -Bao Rui

// View All Foods
app.get('/view-foods', checkAuthenticated, (req, res) => {
  const userID = req.session.user.userID;
  connection.query('SELECT * FROM food_tracker ', (err, results) => {
    if (err) throw err;
    res.render('viewFoods', { foods: results });
  });
});


// View All Exercises!!
app.get('/view-exercises', function (req, res) {
    connection.query('SELECT * FROM exercise_tracker', function (err, results) {
        if (err) throw err;
        res.render('viewExercises', { exercises: results });
    });
});


// update food -Elden ----------------------------------------//
app.get('/updateFood/:id', checkAuthenticated, (req, res) => {
  const foodID = req.params.id;
  const sql = 'SELECT * FROM food_tracker WHERE foodID = ?';  // Fetch food data by ID          
  connection.query(sql, [foodID], (error, results) => {
    if (error) {
      console.error("Error fetching food:", error);
      return res.status(500).send('Error fetching food');
    } else if (results.length === 0) {
      return res.status(404).send('Food not found');
    } else {
      const food = results[0];
      // Only allow if user owns the food or is admin
      if (
        req.session.user.role === 'admin' ||
        food.userID === req.session.user.userID
      ) {
        res.render('updateFood', { food, messages: req.flash('error') });
      } else {
        req.flash('error', 'Unauthorized to update this food entry.');
        return res.redirect('/dashboard');
      }
    }
  });
});

app.post('/updateFood/:id', checkAuthenticated, (req, res) => {
  const foodID = req.params.id;
  const { food_name, carbs, protein, calories, fats } = req.body;

  // First, fetch the food entry to check ownership or admin
  const fetchSql = 'SELECT userID FROM food_tracker WHERE foodID = ?';
  connection.query(fetchSql, [foodID], (fetchErr, results) => {
    if (fetchErr) {
      console.error("Error fetching food for update:", fetchErr);
      return res.status(500).send('Error fetching food');
    }
    if (results.length === 0) {
      return res.status(404).send('Food not found');
    }
    const foodOwnerId = results[0].userID;
    const currentUser = req.session.user;

    // Only allow if current user is owner or admin
    if (currentUser.userID !== foodOwnerId && currentUser.role !== 'admin') {
      req.flash('error', 'Unauthorized to update this food entry.');
      return res.redirect('/dashboard');
    }

    const updateSql = 'UPDATE food_tracker SET food_name = ?, carbs = ?, protein = ?, calories = ?, fats = ? WHERE foodID = ?';
    connection.query(updateSql, [food_name, carbs, protein, calories, fats, foodID], (updateErr) => {
      if (updateErr) {
        console.error("Error updating food:", updateErr);
        return res.status(500).send('Error updating food');
      }
      res.redirect('/dashboard');
    });
  });
});
//---------------------------------------------------------------//

app.get('/updateUser/:id', checkAuthenticated, checkAdmin, (req, res) => {
  const userID = req.params.id;
  const sql = 'SELECT * FROM user WHERE userID = ?';
  connection.query(sql, [userID], (err, results) => {
    if (err) {
      req.flash('error','DB error');
      return res.redirect('/admin');
    }
    if (!results.length) {
      req.flash('error','User not found');
      return res.redirect('/admin');
    }
    res.render('updateUser', {
      user:        req.session.user,
      selectedUser: results[0],
      messages:    req.flash('error')
    });
  });
});

app.post('/updateUser/:id', checkAuthenticated, checkAdmin, (req, res) => {
  const id = req.params.id;
  const { username, email_address, phone_number, age, gender, role } = req.body;
  const sql = `
    UPDATE user
       SET username = ?, email_address = ?, phone_number = ?, age = ?, gender = ?, role = ?
     WHERE userID = ?
  `;
  connection.query(sql,
    [username, email_address, phone_number, age, gender, role, id],
    (err) => {
      if (err) {
        console.error('Update error:', err);
        req.flash('error','Could not update user');
        return res.redirect(`/updateUser/${id}`);
      }
      req.flash('success','User updated');
      res.redirect('/admin');
    }
  );
});

app.post('/deleteUser/:id', checkAuthenticated, checkAdmin, (req, res) => {
  const id = req.params.id;
  const sql = 'DELETE FROM user WHERE userID = ?';
  connection.query(sql, [id], (err) => {
    if (err) {
      console.error('Delete error:', err);
      req.flash('error', 'Delete failed');
    } else {
      req.flash('success', 'User deleted');
    }
    res.redirect('/admin');
  });
});

app.get('/deleteExercise/:id', (req, res) => {
    const exerciseID = req.params.id;
    const sql = 'DELETE FROM exercise_tracker WHERE exerciseID = ?';
    
    // Delete the product from the database
    connection.query(sql, [exerciseID], (error, results) => {
        if (error) {
            console.error('Error deleting exercise:', error);
            res.status(500).send('Error deleting exercise');
        } else {
            res.redirect('/');
        }
    });
});

app.get('/deleteFood/:id', (req, res) => {
    const foodID = req.params.id;
    const sql = 'DELETE FROM food_tracker WHERE foodID = ?';
    
    // Delete the product from the database
    connection.query(sql, [foodID], (error, results) => {
        if (error) {
            console.error('Error deleting food:', error);
            res.status(500).send('Error deleting food');
        } else {
            res.redirect('/');
        }
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);})


// This is a comment :D