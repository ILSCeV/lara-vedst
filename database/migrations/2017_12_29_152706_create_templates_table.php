<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lara\Club;
use Lara\Schedule;
use Lara\Section;
use Lara\Shift;

class CreateTemplatesTable extends Migration
{
    const BD_TEMPLATE_NAME = 'BD Template';

    const BD_SECTION_NAME = 'bd-Club';

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('templates', function (Blueprint $table) {
            $table->increments('id');
            $table->timestamps();

            $table->string('title');
            $table->string('subtitle');
            $table->smallInteger('type');
            $table->unsignedBigInteger('section_id');
            $table->time('time_preparation_start');
            $table->time('time_start');
            $table->time('time_end');
            $table->longText('public_info');
            $table->longText('private_details');
            $table->boolean('is_private');
        });

        Schema::create('shift_template', function (Blueprint $table) {
            $table->integer('template_id')->unsigned()->index();
            $table->integer('shift_id')->unsigned()->index();

            $table->foreign('template_id')->references('id')->on('templates')->onDelete('cascade');
            $table->foreign('shift_id')->references('id')->on('shifts')->onDelete('cascade');
        });

        Schema::create('section_template', function (Blueprint $table) {
            $table->integer('template_id')->unsigned()->index();
            $table->integer('section_id')->unsigned()->index();

            $table->foreign('template_id')->references('id')->on('templates')->onDelete('cascade');
            $table->foreign('section_id')->references('id')->on('sections')->onDelete('cascade');
        });

        DB::table('schedules')->where('schdl_title', '=', self::BD_TEMPLATE_NAME)
            ->update(['schdl_is_template' => '1']);

        $bdSection = Section::where('title', '=', 'bd-Club')->first();

        $templates = Schedule::where('schdl_is_template', '=', '1')->get();
        $templates->map(function (Schedule $template) use ($bdSection) {

            // get template data
            $shifts = $template->shifts()
                ->with('type')
                ->orderByRaw('position IS NULL, position ASC, id ASC')
                ->get();

            $event = $template->getClubEvent;
            if (is_null($event)) {
                $event = new \Lara\ClubEvent();
                $event->evnt_subtitle = "";
                $event->evnt_type = 0;
                $event->evnt_time_start = '21:00:00';
                $event->evnt_time_end = '01:00:00';
                $event->evnt_public_info = '';
                $event->evnt_private_details = '';
                $event->evnt_is_private = false;
                $event->evnt_is_published = true;
            }
            $title = $template->schdl_title;
            $subtitle = $event->evnt_subtitle;
            $type = $event->evnt_type;

            if ($title != self::BD_TEMPLATE_NAME) {
                $filter = $event->showToSection()->get();
                $section = $event->section;
            } else {
                $section = Section::where('title', '=', self::BD_SECTION_NAME)->first();
                if (is_null($section)) {
                    $section = new Section();
                    $section->title = self::BD_SECTION_NAME;
                    $section->section_uid = hash("sha512", uniqid());
                    $section->save();
                    $club = new Club();
                    $club->clb_title = $section->title;
                    $club->save();
                }
                $filter = collect([$section]);
            }
            $dv = $template->schdl_time_preparation_start;
            $timeStart = $event->evnt_time_start;
            $timeEnd = $event->evnt_time_end;
            $info = $event->evnt_public_info;
            $details = $event->evnt_private_details;
            $private = $event->evnt_is_private;

            $result = new \Lara\Template();
            $result->fill([
                'title' => $title,
                'subtitle' => $subtitle,
                'type' => $type,
                'section_id' => $section->id,
                'time_preparation_start' => $dv,
                'time_start' => $timeStart,
                'time_end' => $timeEnd,
                'public_info' => $info,
                'private_details' => $details,
                'is_private' => $private
            ]);
            $result->save();

            $result->shifts()->sync($shifts->map(function (Shift $shift) {
                return $shift->id;
            })->toArray());
            $result->showToSection()->sync($filter->map(function (Section $section) {
                return $section->id;
            })->toArray());
            $result->save();
            return $result;
        });

        Schema::table("schedules", function (Blueprint $table) {
            $table->dropColumn("schdl_is_template");
        });


    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table("schedules", function (Blueprint $table) {
            $table->boolean("schdl_is_template");
        });
        $templateTitles = DB::table("templates")->select("title")->get()
            ->map(function ($tt) {
                return $tt->title;
            })->toArray();
        DB::table("schedules")->update(["schdl_is_template" => "0"]);
        DB::table("schedules")->whereIn("schdl_title", $templateTitles)
            ->update(["schdl_is_template" => "1"]);

        Schema::drop('section_template');
        Schema::drop('shift_template');
        Schema::drop('templates');

    }
}
