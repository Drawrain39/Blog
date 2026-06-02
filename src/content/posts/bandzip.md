---
title: 免费版Bandzip去广patch
published: 2026-05-28
description: 并非解锁付费，而是在原免费版基础上去除所有广告逻辑
tags: [Bandzip,patch]
category: patch
draft: false
---
> ## Bandzip去广patch逻辑（仅免费版） 仅供学习交流使用

# skin\.data

找到data下的skin\.data拖出来 改成zip后缀解压

skin\.xs文件开头就有

```Plain Text
int        g_regShowBallon = 1;
int        g_regShowAd = 1;
int        g_regShowLaunchBar = 1;
```

ShowAd =  1 广告默认开启

直接改成

```Plain Text
int    g_regShowAd = 0;
```

同时存在隐藏

```Plain Text
void HideAd()
{
        Hide(STATIC_WEB_AD1);
        Hide(STATIC_WEB_AD2);
        g_regShowAd = FALSE;
}
```

但是

```Java
void DoInit()
{
        // 크기 조절 이벤트 핸들러 등록
        SetEventHandler(SKINEVENT_ONSIZE, "OnSize();");

        // 레지스트리 값에 따라서 UI 숨기기
        if (g_regShowBallon == FALSE)
                HideBallon();

        //if (g_regShowAd == FALSE)
        //        HideAd();

        if (g_regShowLaunchBar == FALSE)
                HideLaunchBar();
}
```

高光部分被注释掉了，实际上根本没有调用隐藏流程，那直接取消注释就行了

```Java
void DoInit()
{
        // 크기 조절 이벤트 핸들러 등록
        SetEventHandler(SKINEVENT_ONSIZE, "OnSize();");

        // 레지스트리 값에 따라서 UI 숨기기
        if (g_regShowBallon == FALSE)
                HideBallon();

        if (g_regShowAd == FALSE)
                HideAd();

        if (g_regShowLaunchBar == FALSE)
                HideLaunchBar();
}
```

在**skin\_main\.xml**中，搜寻到了static\_ad，所以要在xs里面也把这个隐藏

```Plain Text
void HideAd()
{
        Hide(STATIC_AD);
        Hide(STATIC_WEB_AD1);
        Hide(STATIC_WEB_AD2);
        g_regShowAd = FALSE;
}
```

现在可以初始化主动隐藏广告了



然后接下来要改的就是几个独立的广告窗口 skin\_ad\.xml  skin\_ad\_mg\.xml

```XML
<Window WindowHandle="WINDOW_AD1" Align="client" Margin="0,0,0,0" Padding="0,0,0,0"/>
```

加个Show=false

```XML
<Window WindowHandle="WINDOW_AD1" Align="client" Margin="0,0,0,0" Padding="0,0,0,0" Show="false"/>
```

skin\_ad\_mg\.xml也是一样

```XML
<Window WindowHandle="WINDOW_AD1" Align="top" Height="600" Margin="0,0,0,0" Padding="0,0,0,0"/>
```

改

```XML
<Window WindowHandle="WINDOW_AD1" Align="client" Margin="0,0,0,0" Padding="0,0,0,0" Show="false"/>
```

下一个

```XML
<Button ID="BTN_AD_BUY" 
                        Align="bottom" Height="70" TextMargin="0,20,0,20" Image="btn_btnbg.png" 
                        ImageType="fillframe" Text="Buy now."  
                        HtmlText="true"
                        TextFormat="left,vcenter" 
                        FontWeight="normal" 
                        FontColor="black" FontSize="10" Margin="5,5,5,5" 
                        
                        _FontFace="맑은 고딕" />
                
```

改

```XML
<Button ID="BTN_AD_BUY" 
                        Align="bottom" Height="70" TextMargin="0,20,0,20" Image="btn_btnbg.png" 
                        ImageType="fillframe" Text="Buy now."  
                        HtmlText="true"
                        TextFormat="left,vcenter" 
                        FontWeight="normal" 
                        FontColor="black" FontSize="10" Margin="5,5,5,5" Show="false" 
                        
                        _FontFace="맑은 고딕" />
                
```

**skin\_ask\_appinstall\.xml也有**

```XML
<Button Align="right" Width="130" ID="IDOK" Text="$TEXT_INSTALL_START" Image="default" Margin="0,5,0,5" TextFormat="center" Show="false" />
```

```SQL
<Button Align="left" Width="fit2text" Text="$TEXT_INSTALL_HONEYVIEW_LINK"
                                ID="CMD_OPEN_BANDIVIEW_HOMEPAGE"
                            Padding="0,8,0,8" Margin="0,5,0,50" TextFormat="center"
                            FontColor="black"
                            FontColorHover="blue"
                            Cursor="IDC_HAND" Show="false"
```

改**skin\_main\.xml**

```XML
<Static ID="STATIC_AD" Align="client" Margin="0,10,0,0" Show="false" >
```

```XML
<Static ID="STATIC_WEB_AD1" Align="rightbottom" Image="static_ad.png" ImageType="fillframe" Width="680" Height="165" Margin="0,5,5,0" Show="false" >
```

```XML
<Static ID="STATIC_WEB_AD2" Align="bottom" Height="165" Color="#dddddd" Margin="0,0,0,0" Show="false" >
```

---

# skin\.recovery\.data

同理，里面只有main\.xml 

```XML
<Button ID="IDC_BTN_BUY_NOW" Align="center" Height="22" Width="fit2text" Text="$BUTTON_BUY_NOW"
    FontColor="#333333"
    FontColorHover="#779312"
    FontUnderlineHover ="true"
    Image="btn_buy.png" ImageType="default" TextMargin="0,0,0,27" Margin="7,10,0,0"
    Cursor="IDC_HAND"Show="false"
```

齐了，就patch这些，然后你就可以收获一个免费版无广bandzip了


