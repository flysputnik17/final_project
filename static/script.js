$(function() {

    $('.btn btn-info.calendar').on('click', function(event) {
      $('.dropdown-menu').slideToggle();
      event.stopPropagation();
    });
  
    $('.dropdown-menu.calendar').on('click', function(event) {
      event.stopPropagation();
    });
  
  
  
    $(window).on('click', function() {
      $('.dropdown-menu.calendar').slideUp();
    });
  
  });