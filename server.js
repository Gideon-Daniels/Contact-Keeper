const express = require('express');

const app = express();

app.get('/', (req, res) => 
    res.json({ msg: 'Welcome to the ContactKeeper API...'})
);

// Define Routes
app.use('/api/users', require('./routes/users'));
app.use('/api/auth', require('./routes/auth'));
app.use('/api/contacts', require('./routes/contacts'));

const PORT = process.env.PORT || 5000; 
// look for environment variable called port and this will be used
//  in production

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
