Курсовая работа студента второго курса МГТУ им.Н.Э.Баумана группы ИУ8-31.
Тема работы: Разработка утилиты для обнаружения и эксплуатации популярных веб-уязвимостей с возможностью добавления новых модулей.
Техническое задание: Провести анализ методов атак на современные веб-приложения. Выбрать наиболее значимые веб-уязвимости за 2020-2022 и проанализировать методы их эксплуатации. Провести проектирование утилиты для обнаружения и эксплуатации известных веб-уязвимостей. Разработать исходные коды программы, выпол-нить отладку и тестирование, разработать документацию

В качестве среды для проведения атак, были выбраны докер образы сайтов, взятые с github репозитория(https://github.com/vulhub/vulhub) с различными WEB-уязвимостями, такими как:
  1) SQL инъекция
  2) RCE
  3) File content disclosure (раскрытие содержимого файла) и другие

Исходный код написанный на языке программирования Python содержится в файле "scaner.py"
