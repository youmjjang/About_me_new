const tabs = [...document.querySelectorAll('.tab')];
const panels = [...document.querySelectorAll('.strength-panel')];

function activateTab(tab) {
  const targetId = tab.dataset.target;

  tabs.forEach((item) => {
    const active = item === tab;
    item.classList.toggle('is-active', active);
    item.setAttribute('aria-selected', String(active));
    item.setAttribute('tabindex', active ? '0' : '-1');
  });

  panels.forEach((panel) => {
    const active = panel.id === targetId;
    panel.hidden = !active;
    panel.classList.toggle('is-visible', active);
  });
}

tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => activateTab(tab));

  tab.addEventListener('keydown', (event) => {
    if (!['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();

    let nextIndex = index;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') nextIndex = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') nextIndex = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = tabs.length - 1;

    tabs[nextIndex].focus();
    activateTab(tabs[nextIndex]);
  });
});

const imageDialog=document.querySelector('.image-dialog');
document.querySelectorAll('.shot-open').forEach(button=>button.addEventListener('click',()=>{
 const source=button.querySelector('img'); const target=document.querySelector('#expanded-image');
 target.src=source.src;target.alt=source.alt;document.querySelector('#image-label').textContent=source.alt;
 imageDialog.showModal();
}));
document.querySelector('#close-image').addEventListener('click',()=>imageDialog.close());
imageDialog.addEventListener('click',e=>{if(e.target===imageDialog){const r=imageDialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)imageDialog.close();}});

