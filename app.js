const express = require('express');
const logger = require('morgan');
const path = require('path');
const app = express();
const port = process.env.PORT || '3000';

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static('public'));

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.render('index')
});

app.get('*', (req, res) => {
    res.redirect('/')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
});