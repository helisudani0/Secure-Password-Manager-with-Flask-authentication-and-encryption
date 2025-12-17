function reveal(id) {
  const mask = document.getElementById(`mask-${id}`);
  const real = document.getElementById(`real-${id}`);

  const isHidden = real.classList.contains("hidden");

  if (isHidden) {
    mask.classList.add("hidden");
    real.classList.remove("hidden");

    // auto-hide after 8 seconds
    setTimeout(() => {
      real.classList.add("hidden");
      mask.classList.remove("hidden");
    }, 8000);
  } else {
    real.classList.add("hidden");
    mask.classList.remove("hidden");
  }
}


function copySecret(id) {
  const real = document.getElementById(`real-${id}`);

  navigator.clipboard.writeText(real.innerText).then(() => {
    alert("Password copied securely");
  });
}



function generatePassword() {
  fetch('/generate_password')
    .then(res => res.json())
    .then(data => {
      document.getElementById('password').value = data.password;
    });
}
