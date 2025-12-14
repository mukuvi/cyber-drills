const express = require('express');
const bodyParser = require('body-parser');
const pug = require('pug');
const { VM } = require('vm2');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use('/static', express.static(path.join(__dirname, 'static')));

function sanitizeTemplate(template) {
  const forbiddenPatterns = [
    /require/i,
    /process/i,
    /Function/i,
    /global/i,
    /mainModule/i,
    /\bfs\b/i,
    /child_process/i,
    /exec/i,
    /spawn/i,
    /fork/i,
    /eval/i,
    /constructor/i,
    /prototype/i,
  ];

  for (const pattern of forbiddenPatterns) {
    if (pattern.test(template)) {
      throw new Error('Forbidden pattern detected in template.');
    }
  }

  return template;
}

app.get('/', (req, res) => {
  res.render('index', { result: null, error: null });
});

app.post('/render', (req, res) => {
  const userTemplate = req.body.template;

  try {
    sanitizeTemplate(userTemplate);

    const compiledTemplate = pug.compile(userTemplate);
    const vm = new VM({ timeout: 1000, sandbox: { username: "Player" } });
    const output = vm.run(`\`${compiledTemplate({})}\``);
    res.render('index', { result: output, error: null });
  } catch (err) {
    res.render('index', { result: null, error: err.message });
  }
});

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Challenge running at http://localhost:${PORT}`);
});
