"use strict";

var g_name= '';
var g_type = '';
var g_search = '';
var g_title = '';
var g_title_type = ''
var max_datapoints = 120;

function set_ip_click_handler() {
    $(".ip_addr").unbind("click");
    $(".ip_addr").click(function(event) {
        $("#dns_popup").modal('show');
        $("#dns_popup_content").text("Loading....");
//        window.open('https://dnschecker.org/ip-whois-lookup.php?query=' + encodeURIComponent($(this).text()));
        $.ajax({
            url: script_root +"/reverse_dns/"+ encodeURIComponent($(this).text()) ,
            type: "GET"
        }).done(function(data) {
            console.log('foo')
            console.log(data)
            $("#dns_popup_content").html(data);
            $("#dns_popup").modal("handleUpdate")
        });
    })

}

function handle_request(name, type, search, title, title_type)
{
    var host = $("#host_selector").find(":selected").val()
    g_name = name;
    g_type = type;
    g_search = search;
    g_title = title;
    g_title_type = title_type;
    var period = 'today';
    if ($("#daily").is(":checked")) {period = 'today';}
    else if ($("#hourly").is(":checked")) {period = 'hour';}
    else if ($("#yesterday").is(":checked")) {period = 'yesterday';}
    else if ($("#weekly").is(":checked")) {period = 'week';}
    else if ($("#monthly").is(":checked")) {period = 'month';}
    $('#itemstable').html('');
    $.ajax({
        url: script_root + '/data/',
        type: 'POST',
        data: JSON.stringify({'name': name, "type": type, 'period': period, 'search': search, 'host': host}),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        $('#itemstable').html(res.rhtml);
        document.title = ("Log Analyser - " + title_type + " " + name +  " " + period).replace("_", " ");
        $("#header").text((title_type + ": " + title).replace("_", " "));
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
        var title =$(this).text();
        handle_request(name, type, '', title, $(this).attr("data-type"))
    });
    $("[id^='apache_']").click(function(event) {
        var type = "apache";
        var name = $(this).attr("id").replace('apache_', '');
        var title =$(this).text();
        handle_request(name, type, '', title, $(this).attr("data-type"))
    });
    $("[name^='timeperiod").click(function(event) {
       handle_request(g_name, g_type, g_search, g_title, g_title_type);
    });
    $("#searchbutton").click(function(event) {
        handle_request(g_name, g_type, $("#searchbar").val(), g_title, g_title_type);
    });
    $("#host_selector").change(function() {
        handle_request(g_name, g_type, $("#searchbar").val(), g_title, g_title_type);
    });
}


$( document ).ready(function() {
    set_hosts()

    $('body').css('background-image', 'url("' + script_root + '/static/img/necronomicon.png")');
    $('body').css('background-size', 'contain');
    $('#itemstablediv').scrollTop(0);

    set_log_handlers();
    handle_request('users', "ssh", '', 'Users', "SSH");
});
