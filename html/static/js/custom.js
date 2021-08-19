
var g_name= '';
var g_type = '';
var g_search = '';
var max_datapoints = 120;

function set_ip_click_handler() {
    $(".ip_addr").unbind("click");
    $(".ip_addr").click(function(event) {
        window.open('https://dnschecker.org/ip-whois-lookup.php?query=' + encodeURIComponent($(this).text()));
//        console.log('http://www.whois.com/whois/' + encodeURIComponent($(this).text()));
        console.log($(this).text());

    });
    }

function handle_request(name, type, search)
{
    console.log(name, type, search)
    g_name = name;
    g_type = type;
    g_search = search;
   var period = 'today';
    if ($("#daily").is(":checked")) {period = 'today';}
    else if ($("#hourly").is(":checked")) {period = 'hour';}
    else if ($("#yesterday").is(":checked")) {period = 'yesterday';}
    else if ($("#weekly").is(":checked")) {period = 'week';}
    else if ($("#monthly").is(":checked")) {period = 'month';}
    console.log(period);
    $.ajax({
        url: script_root + '/data/',
        type: 'POST',
        data:  JSON.stringify({'name': name, "type": type, 'period': period, 'search': search}),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        $('#itemstable').html(res.rhtml);
        document.title = ("Log Analyser - " + type + " " + name +  " " + period).replace("_", " ");
        $("#header").text((type + ": " + name).replace("_", " "));
        set_ip_click_handler();
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
    $("[name^='timeperiod").click(function(event) {
       handle_request(g_name, g_type, g_search);
    });
    $("#searchbutton").click(function(event) {
        handle_request(g_name, g_type, $("#searchbar").val())
    });
}


$( document ).ready(function() {
    add_items_lock = 0
    $('body').css('background-image', 'url("' + script_root + '/static/img/background.gif")');
    $('body').css('background-size', 'contain');
    $('#itemstablediv').scrollTop(0);
    set_log_handlers();
    handle_request('users', "ssh", '');
});
