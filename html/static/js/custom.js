$( document ).ready(function() {
       
    add_items_lock = 0
    $('body').css('background-image', 'url("' + script_root + '/static/img/background.gif")');
    $('body').css('background-size', 'contain');




    $('#itemstablediv').scrollTop(0);

    set_log_handlers();

    function handle_request(name, type) {
        console.log(name, type)
        $.ajax({
            url: script_root + '/data/',
            type: 'POST',
            data:  JSON.stringify({'name': name, "type": type}),
            cache: false,
            contentType: "application/json;charset=UTF-8",

        }).done(function(data) {
            var res = JSON.parse(data)
            console.log(res);
            $('#itemstable').html(res.rhtml);
        });
        return false;
    }


    function set_log_handlers()
    {
        $("[id^='ssh_']").unbind('click');
        $("[id^='apache_']").unbind('click');

        $("[id^='ssh_']").click(function(event) {
            var type = "ssh";
            var name = $(this).attr("id").replace('ssh_', '');
            handle_request(name, type)
        });
        $("[id^='apache_']").click(function(event) {
            var type = "apache";
            var name = $(this).attr("id").replace('apache_', '');
            handle_request(name, type)
        });
        }

});
