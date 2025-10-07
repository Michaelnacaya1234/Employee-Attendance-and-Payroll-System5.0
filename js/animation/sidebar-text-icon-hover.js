// Sidebar with Text and Icon Hover Animations
document.addEventListener('DOMContentLoaded', function() {
  // Initialize sidebar with text and icon hover animations
  initSidebarTextIconHover();
});

function initSidebarTextIconHover() {
  // Get all sidebar menu items
  const menuItems = document.querySelectorAll('aside nav a, aside nav button');
  const sidebar = document.querySelector('aside');
  
  // Show all menu items immediately without fade-in effect
  menuItems.forEach(item => {
    item.style.opacity = '1';
    item.style.transform = 'translateX(0)';
  });
  
  // Show sidebar immediately without sliding animation
  sidebar.style.opacity = '1';
  sidebar.style.transform = 'translateX(0)';
  
  // Add hover animations for both icons and text
  menuItems.forEach(item => {
    // Set initial transition for smooth animations
    item.style.transition = 'background-color 0.2s ease-out, transform 0.2s ease-out';
    
    const icon = item.querySelector('svg');
    const text = item.querySelector('span');
    
    // Set initial transitions for icon and text
    if (icon) {
      icon.style.transition = 'transform 0.2s ease-out';
    }
    
    if (text) {
      text.style.transition = 'transform 0.2s ease-out';
    }
    
    // Hover effect for both icon and text
    item.addEventListener('mouseenter', () => {
      // Background color change
      item.style.backgroundColor = 'rgba(255, 255, 255, 0.1)';
      
      // Icon animation (move right)
      if (icon) {
        icon.style.transform = 'translateX(4px)';
      }
      
      // Text animation (move right slightly less than icon)
      if (text) {
        text.style.transform = 'translateX(2px)';
      }
    });
    
    // Mouse leave effect for both icon and text
    item.addEventListener('mouseleave', () => {
      // Reset background color
      item.style.backgroundColor = '';
      
      // Reset icon position
      if (icon) {
        icon.style.transform = 'translateX(0)';
      }
      
      // Reset text position
      if (text) {
        text.style.transform = 'translateX(0)';
      }
    });
  });
  
  // Add active state animations
  const currentPath = window.location.hash || '#dashboard';
  const currentItem = document.querySelector(`a[href="${currentPath}"]`);
  
  if (currentItem) {
    // Apply active state with smooth transition
    currentItem.style.transition = 'background-color 0.3s ease-out, transform 0.3s ease-out';
    currentItem.style.backgroundColor = 'rgba(255, 255, 255, 0.15)';
    
    const currentIcon = currentItem.querySelector('svg');
    const currentText = currentItem.querySelector('span');
    
    if (currentIcon) {
      currentIcon.style.transition = 'transform 0.3s ease-out';
      currentIcon.style.transform = 'translateX(4px)';
    }
    
    if (currentText) {
      currentText.style.transition = 'transform 0.3s ease-out';
      currentText.style.transform = 'translateX(2px)';
    }
    
    // Maintain active state on hover
    currentItem.addEventListener('mouseenter', () => {
      currentItem.style.backgroundColor = 'rgba(255, 255, 255, 0.15)';
    });
    
    currentItem.addEventListener('mouseleave', () => {
      currentItem.style.backgroundColor = 'rgba(255, 255, 255, 0.15)';
    });
  }
}