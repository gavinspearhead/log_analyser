"use strict";

var g_name= '';
var g_type = '';
var g_search = '';
var g_title = '';
var g_title_type = ''
var max_datapoints = 120;


function handle_request(name, type, search, title, title_type)
{
    var host = $("#host_selector").find(":selected").val()
    g_name = name;
    g_type = type;
    g_search = search;
    g_title = title;
    g_title_type = title_type;
    let {period, from, to} = get_period()
    $('#itemstable').html('');
    $.ajax({
        url: script_root + '/data/',
        type: 'POST',
        data: JSON.stringify({'name': name, "type": type, 'period': period,  'to': to, 'from':from,'search': search, 'host': host}),
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
    $("[id^='nntp_proxy_']").unbind('click');
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
    $("[id^='nntp_proxy_']").click(function(event) {
        var type = "nntp_proxy";
        var name = $(this).attr("id").replace('nntp_proxy_', '');
        var title =$(this).text();
        handle_request(name, type, '', title, $(this).attr("data-type"))
    });
    $("[name^='timeperiod").click(function(event) {
        if ($(this).attr('id') != 'custom')  {
            handle_request(g_name, g_type, g_search, g_title, g_title_type);
        }
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
    $('.dropdown-toggle').dropdown()
    $('body').css('background-image', 'url("' + script_root + '/static/img/necronomicon.png")');
    $('body').css('background-size', 'contain');
    $('#itemstablediv').scrollTop(0);
    set_log_handlers();
    $("#submit_custom").click(function() {
        $("#custom").prop("checked", true);
        $('#custom').dropdown('toggle');
        handle_request(g_name, g_type, g_search, g_title, g_title_type);
    });

    $("#custom").click(function() {
        $("#custom").prop("checked", true);
    });
    handle_request('users', "ssh", '', 'Users', "SSH");
});
