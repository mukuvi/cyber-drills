const updateBackground = () => {
    const bg = document.querySelector('.dynamic-background');
    const hue = Math.floor(Math.random() * 360);
    bg.style.background = `radial-gradient(circle, hsla(${hue}, 100%, 50%, 0.2), hsla(${(hue + 180) % 360}, 100%, 50%, 0.1))`;
  };
  
  setInterval(updateBackground, 5000);
  